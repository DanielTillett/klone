/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* Declarative request validation (doc/VALIDATE): a vhost's "validators"
 * define named checks (a regular expression, an integer range, a length
 * range, a list of values) and its "params" blocks, per path and method,
 * say which parameters a page takes, from where, checked by which
 * validator. A page then only sees parameters that passed: an invalid or
 * missing required one gets 400 (or, with on_invalid drop, is removed),
 * and the arguments no rule names are dropped (or refused). */

#include "klin_conf.h"
#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <u/libu.h>
#include <klin/http.h>
#include <klin/request.h>
#include <klin/validate.h>
#include <klin/vars.h>
#include <klin/vhost.h>

enum { VALID_REGEX, VALID_INT, VALID_LENGTH, VALID_ENUM };

struct validator_s
{
    const char *name;
    int type;
    regex_t re;             /* VALID_REGEX, matched against the whole value */
    long long min, max;     /* VALID_INT, VALID_LENGTH                         */
    const char *values;     /* VALID_ENUM, blank separated                  */
};

/* parse a whole decimal integer (optional '-', digits, nothing else) */
static int valid_int(const char *s, long long *pv)
{
    char *end;

    if(s == NULL || *s == '\0' || (*s != '-' && (*s < '0' || *s > '9')))
        return ~0;
    errno = 0;
    *pv = strtoll(s, &end, 10);
    return (errno || *end) ? ~0 : 0;
}

/* does 'value' pass validator 'v'? */
static int valid_check(const validator_t *v, const char *value, size_t len)
{
    long long n;
    const char *p, *e;

    switch(v->type)
    {
    case VALID_REGEX:
        return regexec(&v->re, value, 0, NULL, 0) == 0;
    case VALID_INT:
        return valid_int(value, &n) == 0 && n >= v->min && n <= v->max;
    case VALID_LENGTH:
        return (long long) len >= v->min && (long long) len <= v->max;
    case VALID_ENUM:
        for(p = v->values; *p; p = e)
        {
            p += strspn(p, " \t");
            e = p + strcspn(p, " \t");
            if(e > p && (size_t) (e - p) == len && !memcmp(p, value, len))
                return 1;
        }
        return 0;
    }
    return 0;
}

static const validator_t *valid_find(vhost_t *vhost, const char *name)
{
    size_t i;

    for(i = 0; name && i < vhost->nvalidators; ++i)
        if(!strcmp(vhost->validators[i].name, name))
            return &vhost->validators[i];
    return NULL;
}

/* the params block for this path and method, or NULL */
static u_config_t *valid_find_params(vhost_t *vhost, const char *path,
        const char *method)
{
    u_config_t *pb, *pc;
    const char *pat, *m, *e;
    size_t n = strlen(method);
    int i, j, ok;

    for(i = 0; (pb = u_config_get_child_n(vhost->config, "params", i)); ++i)
    {
        for(ok = 0, j = 0; !ok && (pc = u_config_get_child_n(pb, "path", j));
                ++j)
            ok = (pat = u_config_get_value(pc)) && !fnmatch(pat, path, 0);
        if(!ok)
            continue;
        if((m = u_config_get_subkey_value(pb, "method")) == NULL)
            return pb;
        for(; *m; m = e)
        {
            m += strspn(m, " \t,");
            e = m + strcspn(m, " \t,");
            if((size_t) (e - m) == n && !strncasecmp(m, method, n))
                return pb;
        }
    }
    return NULL;
}

enum { SRC_QUERY = 1, SRC_FORM = 2, SRC_ROUTE = 4, SRC_HEADER = 8 };

static int valid_source(const char *s)
{
    if(s == NULL || !strcasecmp(s, "any"))
        return SRC_QUERY | SRC_FORM | SRC_ROUTE;
    if(!strcasecmp(s, "query"))
        return SRC_QUERY;
    if(!strcasecmp(s, "form"))
        return SRC_FORM;
    if(!strcasecmp(s, "route"))
        return SRC_ROUTE;
    if(!strcasecmp(s, "header"))
        return SRC_HEADER;
    return 0;
}

static int valid_yes(u_config_t *c, const char *key, int def)
{
    int b = def;

    (void) u_config_get_subkey_value_b(c, key, def, &b);
    return b;
}

/* does a rule of the block name the argument 'name' from 'src'? */
static int valid_named(u_config_t *pb, const char *name, int src)
{
    u_config_t *pr;
    const char *n;
    int i;

    for(i = 0; (pr = u_config_get_child_n(pb, "param", i)); ++i)
        if((n = u_config_get_subkey_value(pr, "name")) && !strcmp(n, name) &&
                (valid_source(u_config_get_subkey_value(pr, "source")) & src))
            return 1;
    return 0;
}

/* does an argument pass 'v'? A value with a NUL inside (%00) never does:
   what follows the NUL would not be checked */
static int valid_arg_ok(const validator_t *v, var_t *var)
{
    const char *value = var_get_value(var);
    size_t len = value ? strlen(value) : 0, size = var_get_value_size(var);

    if(value == NULL)
        return valid_check(v, "", 0);
    if(size > len + 1)
        return 0;
    return valid_check(v, value, len);
}

/* the source of an argument in the request's list: a POST value, or one
   from the query string */
static int valid_arg_source(request_t *rq, var_t *v)
{
    vars_t *post = request_get_postargs(rq);
    size_t i;

    for(i = 0; post && i < vars_count(post); ++i)
        if(vars_getn(post, i) == v)
            return SRC_FORM;
    return SRC_QUERY;
}

/* check one rule; 0, or the status to answer with */
static int valid_rule(request_t *rq, u_config_t *pr, const validator_t *v,
        int drop)
{
    const char *name = u_config_get_subkey_value(pr, "name"), *value;
    int src = valid_source(u_config_get_subkey_value(pr, "source")), found = 0;
    vars_t *args = request_get_args(rq), *route = request_get_route_params(rq);
    var_t *var;
    size_t i;

    if(src & SRC_HEADER)
    {
        if((value = request_get_field_value(rq, name)) != NULL)
        {
            if(v && !valid_check(v, value, strlen(value)))
                return HTTP_STATUS_BAD_REQUEST;     /* not removed: refuse */
            found = 1;
        }
    }

    /* the request's arguments (each value of a repeated name), then the
       route's */
    for(i = 0; (src & (SRC_QUERY | SRC_FORM)) && args && i < vars_count(args);)
    {
        var = vars_getn(args, i);
        if(strcmp(var_get_name(var), name) ||
                !(valid_arg_source(rq, var) & src))
        {
            ++i;
            continue;
        }
        if(v && !valid_arg_ok(v, var))
        {
            if(!drop)
                return HTTP_STATUS_BAD_REQUEST;
            dbg_err_if(request_del_arg(rq, var));
            continue;
        }
        found = 1;
        ++i;
    }
    for(i = 0; (src & SRC_ROUTE) && route && i < vars_count(route);)
    {
        var = vars_getn(route, i);
        if(strcmp(var_get_name(var), name))
        {
            ++i;
            continue;
        }
        if(v && !valid_check(v, var_get_value(var), strlen(var_get_value(var))))
        {
            if(!drop)
                return HTTP_STATUS_BAD_REQUEST;
            dbg_err_if(vars_del(route, var));
            var_free(var);
            continue;
        }
        found = 1;
        ++i;
    }

    if(!found && valid_yes(pr, "required", 0))
        return HTTP_STATUS_BAD_REQUEST;

    return 0;
err:
    return HTTP_STATUS_INTERNAL_SERVER_ERROR;
}

/**
 * \brief   Validate a request's parameters
 *
 * If a params block of the vhost matches \p path (the path the client
 * asked for) and the method, parse the arguments and the form body and
 * check them against its rules.
 *
 * \return \c 0 to serve the page, or the status to answer with (400, or
 *         what parsing the body failed with)
 */
int validate_request(http_t *h, request_t *rq, const char *path)
{
    const char *unknown;
    u_config_t *pb, *pr;
    vhost_t *vhost;
    vars_t *args;
    var_t *var;
    size_t i;
    int rc, drop;

    dbg_return_if (h == NULL || rq == NULL || path == NULL,
            HTTP_STATUS_INTERNAL_SERVER_ERROR);

    if((vhost = http_get_vhost(h, rq)) == NULL || !vhost->has_params)
        return 0;
    if((pb = valid_find_params(vhost, path, request_get_method_name(rq)))
            == NULL)
        return 0;

    if((rc = request_parse_data(rq)) != 0)
        return rc;

    drop = (u_config_get_subkey_value(pb, "on_invalid") != NULL &&
            !strcasecmp(u_config_get_subkey_value(pb, "on_invalid"), "drop"));

    for(i = 0; (pr = u_config_get_child_n(pb, "param", i)); ++i)
        if((rc = valid_rule(rq, pr,
                        valid_find(vhost, u_config_get_subkey_value(pr,
                                "validator")), drop)) != 0)
            return rc;

    /* the arguments no rule names: dropped (default), refused or kept */
    unknown = u_config_get_subkey_value(pb, "unknown");
    if(unknown && !strcasecmp(unknown, "allow"))
        return 0;
    for(i = 0; (args = request_get_args(rq)) && i < vars_count(args);)
    {
        var = vars_getn(args, i);
        if(valid_named(pb, var_get_name(var), valid_arg_source(rq, var)))
        {
            ++i;
            continue;
        }
        if(unknown && !strcasecmp(unknown, "reject"))
            return HTTP_STATUS_BAD_REQUEST;
        dbg_err_if(request_del_arg(rq, var));
    }

    return 0;
err:
    return HTTP_STATUS_INTERNAL_SERVER_ERROR;
}

/**
 * \brief   Load a vhost's validators and check its params blocks (a bad
 *          one stops the server)
 */
int validate_load(vhost_t *vhost)
{
    u_config_t *vs, *vc, *pb, *pr;
    validator_t *v;
    const char *s, *name;
    char *pat = NULL;
    long long a, b;
    char ka[32], kb[32];
    int i, j, n;
    size_t len;

    dbg_return_if (vhost == NULL, ~0);

    if((vs = u_config_get_child(vhost->config, "validators")) != NULL)
    {
        for(n = 0; u_config_get_child_n(vs, "validator", n); ++n)
            ;
        if(n)
            dbg_err_if((vhost->validators = u_zalloc(n * sizeof *v)) == NULL);

        for(i = 0; (vc = u_config_get_child_n(vs, "validator", i)); ++i)
        {
            v = &vhost->validators[vhost->nvalidators];
            name = u_config_get_subkey_value(vc, "name");
            warn_err_ifm(name == NULL, "validators: a validator has no name");
            warn_err_ifm(valid_find(vhost, name) != NULL,
                    "validators: %s is defined twice", name);
            v->name = name;

            if((s = u_config_get_subkey_value(vc, "regex")) != NULL)
            {
                v->type = VALID_REGEX;
                len = strlen(s) + 5;
                dbg_err_if((pat = u_malloc(len)) == NULL);
                (void) u_snprintf(pat, len, "^(%s)$", s);
                warn_err_ifm(regcomp(&v->re, pat, REG_EXTENDED | REG_NOSUB),
                        "validators: %s: bad regular expression", name);
                U_FREE(pat);
            } else if((s = u_config_get_subkey_value(vc, "int")) != NULL ||
                    (s = u_config_get_subkey_value(vc, "length")) != NULL) {
                v->type = u_config_get_subkey_value(vc, "int") ? VALID_INT :
                    VALID_LENGTH;
                warn_err_ifm(sscanf(s, "%31s %31s", ka, kb) != 2 ||
                        valid_int(ka, &a) || valid_int(kb, &b) || a > b ||
                        (v->type == VALID_LENGTH && a < 0),
                        "validators: %s: give a minimum and a maximum", name);
                v->min = a;
                v->max = b;
            } else if((s = u_config_get_subkey_value(vc, "enum")) != NULL) {
                v->type = VALID_ENUM;
                v->values = s;
            } else
                warn_err("validators: %s needs regex, int, length or enum",
                        name);
            vhost->nvalidators++;
        }
    }

    /* every rule names a parameter, a known source and a defined
       validator */
    for(i = 0; (pb = u_config_get_child_n(vhost->config, "params", i)); ++i)
    {
        vhost->has_params = 1;
        warn_err_ifm(u_config_get_child(pb, "path") == NULL,
                "params: a block has no path");
        s = u_config_get_subkey_value(pb, "unknown");
        warn_err_ifm(s && strcasecmp(s, "drop") && strcasecmp(s, "reject") &&
                strcasecmp(s, "allow"), "params: unknown is drop, reject or "
                "allow");
        s = u_config_get_subkey_value(pb, "on_invalid");
        warn_err_ifm(s && strcasecmp(s, "drop") && strcasecmp(s, "reject"),
                "params: on_invalid is drop or reject");
        for(j = 0; (pr = u_config_get_child_n(pb, "param", j)); ++j)
        {
            name = u_config_get_subkey_value(pr, "name");
            warn_err_ifm(name == NULL, "params: a param has no name");
            warn_err_ifm(!valid_source(u_config_get_subkey_value(pr, "source")),
                    "params: %s: source is query, form, route, header or "
                    "any", name);
            s = u_config_get_subkey_value(pr, "validator");
            warn_err_ifm(s && valid_find(vhost, s) == NULL,
                    "params: %s: no validator called %s", name, s);
        }
    }

    return 0;
err:
    U_FREE(pat);
    return ~0;
}

/* free what validate_load() made */
void validate_free(vhost_t *vhost)
{
    size_t i;

    if(vhost == NULL)
        return;
    for(i = 0; i < vhost->nvalidators; ++i)
        if(vhost->validators[i].type == VALID_REGEX)
            regfree(&vhost->validators[i].re);
    U_FREE(vhost->validators);
    vhost->nvalidators = 0;
}
