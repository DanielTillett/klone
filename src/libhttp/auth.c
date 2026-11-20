/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* HTTP authentication of a vhost's realms: Basic (RFC 7617) and Digest
 * (RFC 7616, SHA-256 and, if a realm allows it, MD5). The configuration is
 * described in doc/AUTH.
 *
 * Digest nonces are stateless: "<time><HMAC-SHA256(secret, time:realm)>",
 * with a secret drawn when the server starts (before the prefork workers
 * fork, so every worker accepts the others' nonces). A nonce older than
 * nonce_lifetime is answered with stale=true. Nonce counts are not tracked
 * across workers: a captured request can be replayed within the lifetime,
 * as with most servers; use TLS. */

#include "klin_conf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <u/libu.h>
#include <klin/auth.h>
#include <klin/http.h>
#include <klin/request.h>
#include <klin/response.h>
#include <klin/vhost.h>
#include <klin/utils.h>
#include "http_s.h"

#include <klin/crypto.h>

enum {
    AUTH_SCHEME_BASIC = 1,
    AUTH_SCHEME_DIGEST = 2,
    AUTH_NONCE_LIFETIME = 300,          /* default, seconds                */
    AUTH_BASIC_CACHE = 8,               /* verified Basic credentials kept */
    AUTH_BASIC_CACHE_TTL = 300          /* seconds                         */
};

/* the scheme(s) a realm accepts */
static int auth_realm_schemes(u_config_t *realm)
{
    const char *v = u_config_get_subkey_value(realm, "scheme");

    if(v == NULL || !strcasecmp(v, "digest"))
        return AUTH_SCHEME_DIGEST;
    if(!strcasecmp(v, "basic"))
        return AUTH_SCHEME_BASIC;
    if(!strcasecmp(v, "any"))
        return AUTH_SCHEME_BASIC | AUTH_SCHEME_DIGEST;
    return 0;
}

static int auth_bool(u_config_t *c, const char *key)
{
    int b = 0;

    (void) u_config_get_subkey_value_b(c, key, 0, &b);

    return b;
}

/* is token 'tok' in the blank- or comma-separated 'list'? */
static int auth_in_list(const char *list, const char *tok, size_t toklen)
{
    const char *p = list, *e;

    while(p && *p)
    {
        p += strspn(p, " \t,");
        e = p + strcspn(p, " \t,");
        if((size_t) (e - p) == toklen && !strncmp(p, tok, toklen))
            return 1;
        p = e;
    }

    return 0;
}

/* does the user have one of the realm's roles (any user if it lists none)? */
static int auth_has_role(u_config_t *realm, u_config_t *user)
{
    const char *want = u_config_get_subkey_value(realm, "roles"),
               *have = u_config_get_subkey_value(user, "roles"), *p, *e;

    if(want == NULL || want[strspn(want, " \t,")] == '\0')
        return 1;

    for(p = want; have && *p; p = e)
    {
        p += strspn(p, " \t,");
        e = p + strcspn(p, " \t,");
        if(e > p && auth_in_list(have, p, (size_t) (e - p)))
            return 1;
    }

    return 0;
}

/* the realm protecting 'path', or NULL */
static u_config_t *auth_find_realm(u_config_t *auth, const char *path)
{
    u_config_t *realm, *pc;
    const char *pat;
    int i, j;

    for(i = 0; (realm = u_config_get_child_n(auth, "realm", i)); ++i)
        for(j = 0; (pc = u_config_get_child_n(realm, "path", j)); ++j)
            if((pat = u_config_get_value(pc)) && !fnmatch(pat, path, 0))
                return realm;

    return NULL;
}

static u_config_t *auth_find_user_in(u_config_t *c, const char *name)
{
    u_config_t *user;
    const char *v;
    int i;

    for(i = 0; c && (user = u_config_get_child_n(c, "user", i)); ++i)
        if((v = u_config_get_subkey_value(user, "name")) && !strcmp(v, name))
            return user;

    return NULL;
}

static u_config_t *auth_find_user(vhost_t *vhost, const char *name)
{
    u_config_t *u;

    if((u = auth_find_user_in(vhost->auth, name)) != NULL)
        return u;

    return auth_find_user_in(vhost->auth_users, name);
}

/* the HA1 a user stores for 'realm' and 'alg': a "digest" line
 * "<algorithm> <hex HA1> <realm name>" */
static const char *auth_user_ha1(u_config_t *user, int alg, const char *realm)
{
    static char ha1[AUTH_HEX_SZ];
    char algname[16];
    const char *v, *hex, *rn;
    size_t hl;
    u_config_t *d;
    int i;

    for(i = 0; (d = u_config_get_child_n(user, "digest", i)); ++i)
    {
        if((v = u_config_get_value(d)) == NULL)
            continue;
        hex = v + strcspn(v, " \t");
        if((size_t) (hex - v) >= sizeof algname)
            continue;
        memcpy(algname, v, (size_t) (hex - v));
        algname[hex - v] = '\0';
        hex += strspn(hex, " \t");
        hl = strcspn(hex, " \t");
        rn = hex + hl;
        rn += strspn(rn, " \t");
        if(auth_alg_from_name(algname) == alg && !strcmp(rn, realm) &&
                hl < sizeof ha1)
        {
            memcpy(ha1, hex, hl);
            ha1[hl] = '\0';
            return ha1;
        }
    }

    return NULL;
}

#ifdef SSL_OPENSSL

static int auth_equal(const char *a, const char *b)
{
    size_t la = strlen(a);

    return la == strlen(b) && kc_memeq(a, b, la);
}

/* the nonce for 'realm' issued at 't' */
static int auth_nonce(http_t *h, const char *realm, unsigned long t,
        char *out, size_t size)
{
    unsigned char mac[KC_MD_MAX];
    size_t maclen = 0;
    char ts[32], msg[512], hex[2 * KC_MD_MAX + 1];
    int n;

    n = snprintf(ts, sizeof ts, "%016lx", t);
    dbg_err_if(n < 0 || (size_t) n >= sizeof ts);
    n = snprintf(msg, sizeof msg, "%s:%s", ts, realm);
    dbg_err_if(n < 0 || (size_t) n >= sizeof msg);

    dbg_err_if(kc_hmac(KC_SHA256, h->auth_secret, sizeof h->auth_secret,
                msg, (size_t) n, mac, &maclen));
    u_tohex(hex, (const char *) mac, maclen);

    n = snprintf(out, size, "%s%s", ts, hex);
    dbg_err_if(n < 0 || (size_t) n >= size);

    return 0;
err:
    return ~0;
}

/* 0 if 'nonce' was issued by this server for 'realm'; *stale is set when
 * it is older than the realm's lifetime */
static int auth_nonce_check(http_t *h, u_config_t *auth, const char *realm,
        const char *nonce, int *stale)
{
    char ts[17], want[128], *end;
    unsigned long t;
    int lifetime;

    nop_err_if(strlen(nonce) < 16);
    memcpy(ts, nonce, 16);
    ts[16] = '\0';
    t = strtoul(ts, &end, 16);
    nop_err_if(*end != '\0');

    dbg_err_if(auth_nonce(h, realm, t, want, sizeof want));
    nop_err_if(!auth_equal(nonce, want));

    dbg_err_if(u_config_get_subkey_value_i(auth, "nonce_lifetime",
                AUTH_NONCE_LIFETIME, &lifetime));
    *stale = ((unsigned long) time(NULL) > t + (unsigned long) lifetime);

    return 0;
err:
    return ~0;
}

/* split the next 'name=value' or 'name="value"' of a Digest header;
 * values are written to 'buf' unquoted */
static const char *auth_next_param(const char *p, char *name, size_t nsz,
        char *buf, size_t bsz)
{
    size_t n = 0, v = 0;

    p += strspn(p, " \t,");
    if(*p == '\0')
        return NULL;

    while(*p && *p != '=' && *p != ' ' && *p != '\t' && n + 1 < nsz)
        name[n++] = *p++;
    name[n] = '\0';
    p += strspn(p, " \t");
    if(*p++ != '=')
        return NULL;
    p += strspn(p, " \t");

    if(*p == '"')
    {
        for(++p; *p && *p != '"'; ++p)
        {
            if(*p == '\\' && p[1])
                ++p;
            if(v + 1 >= bsz)
                return NULL;
            buf[v++] = *p;
        }
        if(*p++ != '"')
            return NULL;
    } else {
        while(*p && *p != ',' && *p != ' ' && *p != '\t' && v + 1 < bsz)
            buf[v++] = *p++;
    }
    buf[v] = '\0';

    return p;
}

enum { DP_USER, DP_REALM, DP_NONCE, DP_URI, DP_RESPONSE, DP_ALG, DP_QOP,
    DP_NC, DP_CNONCE, DP_COUNT };

/* check a Digest Authorization; return the user, or NULL */
static u_config_t *auth_digest(http_t *h, request_t *rq, vhost_t *vhost,
        u_config_t *realm, const char *cred, int *stale)
{
    static const char *names[DP_COUNT] = { "username", "realm", "nonce",
        "uri", "response", "algorithm", "qop", "nc", "cnonce" };
    char p[DP_COUNT][512], name[32], val[512], want[AUTH_HEX_SZ];
    const char *rname = u_config_get_subkey_value(realm, "name"), *ha1;
    u_config_t *user;
    int i, alg;

    memset(p, 0, sizeof p);
    while((cred = auth_next_param(cred, name, sizeof name, val, sizeof val)))
        for(i = 0; i < DP_COUNT; ++i)
            if(!strcasecmp(name, names[i]))
                (void) u_strlcpy(p[i], val, sizeof p[i]);

    /* MD5 when the client names no algorithm (RFC 7616 3.3) */
    alg = p[DP_ALG][0] ? auth_alg_from_name(p[DP_ALG]) : AUTH_ALG_MD5;
    nop_err_if(alg == 0);
    nop_err_if(alg == AUTH_ALG_MD5 && !auth_bool(realm, "md5"));

    nop_err_if(!p[DP_USER][0] || strcmp(p[DP_REALM], rname));
    nop_err_if(strcmp(p[DP_QOP], "auth") || !p[DP_NC][0] || !p[DP_CNONCE][0]);

    /* the digest covers this request's target, not another one */
    nop_err_if(strcmp(p[DP_URI], request_get_uri(rq)));

    nop_err_if(auth_nonce_check(h, vhost->auth, rname, p[DP_NONCE], stale));

    nop_err_if((user = auth_find_user(vhost, p[DP_USER])) == NULL);
    nop_err_if((ha1 = auth_user_ha1(user, alg, rname)) == NULL);

    dbg_err_if(auth_digest_response(alg, ha1, p[DP_NONCE], p[DP_NC],
                p[DP_CNONCE], request_get_method_name(rq), p[DP_URI], want));
    nop_err_if(!auth_equal(want, p[DP_RESPONSE]));

    /* right password, old nonce: ask again (stale=true), no new password */
    nop_err_if(*stale);

    return user;
err:
    return NULL;
}

/* Basic credentials verified lately: PBKDF2 is slow on purpose, and a
 * client sends the same header with every request */
static struct { unsigned char key[32]; time_t when; } auth_cache[AUTH_BASIC_CACHE];

static void auth_cache_key(http_t *h, const char *cred, const char *stored,
        unsigned char key[32])
{
    unsigned char mac[KC_MD_MAX];
    char msg[1024];
    int n = snprintf(msg, sizeof msg, "%s\n%s", cred, stored);

    if(n < 0 || (size_t) n >= sizeof msg ||
            kc_hmac(KC_SHA256, h->auth_secret, sizeof h->auth_secret, msg,
                (size_t) n, mac, NULL))
        memset(key, 0, 32);     /* never matches a filled slot */
    else
        memcpy(key, mac, 32);
    kc_cleanse(msg, sizeof msg);
}

static int auth_cache_hit(const unsigned char key[32])
{
    time_t now = time(NULL);
    int i;

    for(i = 0; i < AUTH_BASIC_CACHE; ++i)
        if(auth_cache[i].when && now - auth_cache[i].when < AUTH_BASIC_CACHE_TTL
                && kc_memeq(auth_cache[i].key, key, 32))
            return 1;

    return 0;
}

static void auth_cache_add(const unsigned char key[32])
{
    static int next = 0;

    memcpy(auth_cache[next].key, key, 32);
    auth_cache[next].when = time(NULL);
    next = (next + 1) % AUTH_BASIC_CACHE;
}

/* check a Basic Authorization; return the user, or NULL */
static u_config_t *auth_basic(http_t *h, vhost_t *vhost, const char *cred)
{
    unsigned char raw[512], key[32];
    size_t len = sizeof raw - 1;
    const char *stored;
    u_config_t *user;
    char *colon;

    cred += strspn(cred, " \t");
    nop_err_if(klin_b64_decode(cred, strcspn(cred, " \t"), raw, &len));
    raw[len] = '\0';
    nop_err_if(memchr(raw, '\0', len) != NULL);
    nop_err_if((colon = strchr((char *) raw, ':')) == NULL);
    *colon = '\0';

    nop_err_if((user = auth_find_user(vhost, (char *) raw)) == NULL);
    nop_err_if((stored = u_config_get_subkey_value(user, "password")) == NULL);

    auth_cache_key(h, cred, stored, key);
    if(!auth_cache_hit(key))
    {
        nop_err_if(auth_password_verify(colon + 1, stored));
        auth_cache_add(key);
    }

    kc_cleanse(raw, sizeof raw);

    return user;
err:
    kc_cleanse(raw, sizeof raw);
    return NULL;
}

#endif /* SSL_OPENSSL */

/* the schemes this connection may use in 'realm' (no Basic over plain
 * HTTP unless basic_over_http is set) */
static int auth_offered(http_t *h, vhost_t *vhost, u_config_t *realm)
{
    int s = auth_realm_schemes(realm);

    if(!h->ssl && !auth_bool(vhost->auth, "basic_over_http"))
        s &= ~AUTH_SCHEME_BASIC;

    return s;
}

/**
 * \brief   Authenticate a request
 *
 * If the request path is in one of the vhost's realms, check the
 * Authorization header against the realm's users and roles. Called before
 * the page runs.
 *
 * \return \c 0 to serve the page, ::HTTP_STATUS_UNAUTHORIZED (the error
 *         page then carries the challenges, see auth_challenge()) or
 *         ::HTTP_STATUS_FORBIDDEN
 */
int auth_check(http_t *h, request_t *rq)
{
    const char *path, *cred;
    u_config_t *realm, *user = NULL;
    vhost_t *vhost;
    int offered, stale = 0;

    dbg_return_if (h == NULL || rq == NULL, HTTP_STATUS_FORBIDDEN);

    if((vhost = http_get_vhost(h, rq)) == NULL || vhost->auth == NULL)
        return 0;

    if((path = request_get_filename(rq)) == NULL ||
            (realm = auth_find_realm(vhost->auth, path)) == NULL)
        return 0;

    offered = auth_offered(h, vhost, realm);
    request_set_auth(rq, NULL, realm, 0);

#ifdef SSL_OPENSSL
    if((cred = request_get_field_value(rq, "Authorization")) != NULL)
    {
        if(!strncasecmp(cred, "Digest ", 7) && (offered & AUTH_SCHEME_DIGEST))
            user = auth_digest(h, rq, vhost, realm, cred + 7, &stale);
        else if(!strncasecmp(cred, "Basic ", 6) &&
                (offered & AUTH_SCHEME_BASIC))
            user = auth_basic(h, vhost, cred + 6);
    }
#else
    u_unused_args(cred, offered);
#endif

    if(user == NULL)
    {
        request_set_auth(rq, NULL, realm, stale);
        return HTTP_STATUS_UNAUTHORIZED;
    }

    request_set_auth(rq, u_config_get_subkey_value(user, "name"), realm, 0);

    return auth_has_role(realm, user) ? 0 : HTTP_STATUS_FORBIDDEN;
}

/**
 * \brief   Add the WWW-Authenticate challenges of a 401 response
 *
 * One per scheme and algorithm the realm of the request offers: Digest
 * SHA-256, Digest MD5 (if the realm sets md5), then Basic.
 */
int auth_challenge(http_t *h, request_t *rq, response_t *rs)
{
    char buf[1024], nonce[128];
    const char *rname;
    u_config_t *realm;
    vhost_t *vhost;
    field_t *f = NULL;
    int offered, i, n, algs[2] = { AUTH_ALG_SHA256, AUTH_ALG_MD5 };

    dbg_err_if (h == NULL || rq == NULL || rs == NULL);

    nop_err_if((realm = request_get_auth_realm(rq)) == NULL);
    nop_err_if((vhost = http_get_vhost(h, rq)) == NULL);
    rname = u_config_get_subkey_value(realm, "name");
    offered = auth_offered(h, vhost, realm);

#ifdef SSL_OPENSSL
    if(offered & AUTH_SCHEME_DIGEST)
    {
        dbg_err_if(auth_nonce(h, rname, (unsigned long) time(NULL), nonce,
                    sizeof nonce));

        for(i = 0; i < 2; ++i)
        {
            if(algs[i] == AUTH_ALG_MD5 && !auth_bool(realm, "md5"))
                continue;
            n = snprintf(buf, sizeof buf, "Digest realm=\"%s\", qop=\"auth\", "
                    "algorithm=%s, nonce=\"%s\"%s", rname,
                    auth_alg_name(algs[i]), nonce,
                    request_get_auth_stale(rq) ? ", stale=true" : "");
            dbg_err_if(n < 0 || (size_t) n >= sizeof buf);
            dbg_err_if(field_create("WWW-Authenticate", buf, &f));
            dbg_err_if(header_add_field(response_get_header(rs), f));
            f = NULL;
        }
    }
#else
    u_unused_args(nonce, algs, i);
#endif

    if(offered & AUTH_SCHEME_BASIC)
    {
        n = snprintf(buf, sizeof buf, "Basic realm=\"%s\", charset=\"UTF-8\"",
                rname);
        dbg_err_if(n < 0 || (size_t) n >= sizeof buf);
        dbg_err_if(field_create("WWW-Authenticate", buf, &f));
        dbg_err_if(header_add_field(response_get_header(rs), f));
        f = NULL;
    }

    return 0;
err:
    if(f)
        field_free(f);
    return ~0;
}

/* a realm or user name goes into quoted strings: no quote, backslash or
 * control character */
static int auth_name_ok(const char *s)
{
    for(; s && *s; ++s)
        if(*s == '"' || *s == '\\' || (unsigned char) *s < 0x20)
            return 0;
    return s != NULL;
}

static int auth_check_users(u_config_t *c, const char *where)
{
    u_config_t *user;
    const char *v;
    int i;

    for(i = 0; c && (user = u_config_get_child_n(c, "user", i)); ++i)
    {
        v = u_config_get_subkey_value(user, "name");
        warn_err_ifm(v == NULL || !auth_name_ok(v) || strchr(v, ':'),
                "auth: a user in %s has no name, or a bad one", where);
        v = u_config_get_subkey_value(user, "password");
        warn_err_ifm(v && strncmp(v, "pbkdf2-sha256$", 14),
                "auth: user %s: password must be a klin -c passwd hash "
                "(no plaintext)", u_config_get_subkey_value(user, "name"));
    }

    return 0;
err:
    return ~0;
}

/**
 * \brief   Load and check a vhost's "auth" block
 *
 * Called when the vhost is created: a bad realm or user stops the server
 * with a message, rather than leaving pages unprotected.
 */
int auth_load(http_t *h, vhost_t *vhost)
{
    u_config_t *auth, *realm;
    const char *file, *name;
    int i, s;

    dbg_err_if (h == NULL || vhost == NULL);

    if((auth = u_config_get_child(vhost->config, "auth")) == NULL)
        return 0;

#ifndef SSL_OPENSSL
    warn_err("auth: HTTP authentication needs a build with OpenSSL");
#endif

    vhost->auth = auth;

    if((file = u_config_get_subkey_value(auth, "users_file")) != NULL)
        warn_err_ifm(u_config_load_from_file(file, &vhost->auth_users),
                "auth: cannot load users_file %s", file);

    dbg_err_if(auth_check_users(auth, "auth"));
    dbg_err_if(auth_check_users(vhost->auth_users, "users_file"));

    for(i = 0; (realm = u_config_get_child_n(auth, "realm", i)); ++i)
    {
        name = u_config_get_subkey_value(realm, "name");
        warn_err_ifm(!auth_name_ok(name), "auth: a realm needs a name "
                "(no quotes or backslashes)");
        warn_err_ifm(u_config_get_child(realm, "path") == NULL,
                "auth: realm %s has no path", name);
        warn_err_ifm((s = auth_realm_schemes(realm)) == 0,
                "auth: realm %s: scheme is basic, digest or any", name);
        warn_err_ifm(s == AUTH_SCHEME_BASIC && !h->ssl &&
                !auth_bool(auth, "basic_over_http"), "auth: realm %s: Basic "
                "sends passwords in clear text over HTTP; use TLS, Digest, "
                "or set auth.basic_over_http", name);
    }

    return 0;
err:
    return ~0;
}

/* draw the secret Digest nonces are signed with (once per server) */
int auth_init_secret(http_t *h)
{
    dbg_return_if (h == NULL, ~0);

#ifdef SSL_OPENSSL
    dbg_err_if(kc_random(h->auth_secret, sizeof h->auth_secret));
#endif

    return 0;
#ifdef SSL_OPENSSL
err:
    return ~0;
#endif
}
