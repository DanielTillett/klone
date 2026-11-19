/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef SSL_ON
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif 
#include <u/libu.h>
#include <klin/utils.h>
#include <klin/os.h>
#include <klin/server.h>
#include <klin/context.h>
#include <klin/broker.h>
#include <klin/request.h>
#include <klin/ses_prv.h>
#include <klin/response.h>
#include <klin/backend.h>
#include <klin/io.h>
#include <klin/timer.h>
#include <klin/tls.h>
#include <klin/ses_prv.h>
#include <klin/hook.h>
#include <klin/hookprv.h>
#include <klin/access.h>
#include <klin/vhost.h>
#include <klin/supplier.h>
#include "http_s.h"

enum {
    HTTP_KEEP_ALIVE_TIMEOUT = 5,        /* secs to wait for the next request  */
    HTTP_KEEP_ALIVE_MAX = 100,          /* max requests per connection        */
    HTTP_KEEP_ALIVE_DRAIN_MAX = 65536,  /* max unread body bytes to skip      */
    HTTP_CONN_WBUFSZ = 65536            /* connection write buffer: large
                                           responses go out in large blocks */
};

struct http_status_map_s
{
    int status;
    const char *desc;
} http_status_map[] = {
    { HTTP_STATUS_OK                    , "OK"                      },
    { HTTP_STATUS_NOT_MODIFIED          , "Not Modified"            },
    { HTTP_STATUS_NOT_FOUND             , "Not Found"               },
    { HTTP_STATUS_INTERNAL_SERVER_ERROR , "Internal Server Error"   },
    { HTTP_STATUS_MOVED_PERMANENTLY     , "Moved Permanently"       },
    { HTTP_STATUS_MOVED_TEMPORARILY     , "Moved Temporarily"       },
    { HTTP_STATUS_CREATED               , "Created"                 },
    { HTTP_STATUS_ACCEPTED              , "Accepted"                },
    { HTTP_STATUS_NO_CONTENT            , "No Content"              },
    { HTTP_STATUS_BAD_REQUEST           , "Bad Request"             },
    { HTTP_STATUS_UNAUTHORIZED          , "Unauthorized"            },
    { HTTP_STATUS_FORBIDDEN             , "Forbidden"               },
    { HTTP_STATUS_LENGTH_REQUIRED       , "Content-Length required" },
    { HTTP_STATUS_REQUEST_TOO_LARGE     , "Request data too big"    },
    { HTTP_STATUS_EXT_KEY_NEEDED        , "Key needed"              },
    { HTTP_STATUS_NOT_IMPLEMENTED       , "Not Implemented"         },
    { HTTP_STATUS_BAD_GATEWAY           , "Bad Gateway"             },
    { HTTP_STATUS_SERVICE_UNAVAILABLE   , "Service Unavailable"     },
    { 0                                 , NULL                      }
};

enum { URI_MAX = 2048 };

/* in cgi.c */
int cgi_set_request(request_t *rq);

session_opt_t *http_get_session_opt(http_t *http)
{
    dbg_return_if (http == NULL, NULL);

    return http->sess_opt;
}

u_config_t *http_get_config(http_t* http)
{
    dbg_return_if (http == NULL, NULL);

    return http->config;
}

const char *http_get_status_desc(int status)
{
    struct http_status_map_s *map = http_status_map;
    const char *msg = "Unknown Status Code";

    for( ; map->status; ++map)
        if(map->status == status)
        {
            msg = map->desc;
            break;
        }

    return msg;
}

/* dst = dir + "/" + uri, with each run of slashes reduced to one: what
 * u_path_snprintf(dst, sz, '/', "%s/%s", dir, uri) does, without formatting
 * and in one pass (this is done for every request) */
static int http_path_join(char *dst, size_t sz, const char *dir,
        const char *uri)
{
    const char *part[3], *s;
    size_t i, n = 0;

    dbg_err_if(dst == NULL || sz == 0 || dir == NULL || uri == NULL);

    part[0] = dir;
    part[1] = "/";
    part[2] = uri;

    for(i = 0; i < 3; ++i)
    {
        for(s = part[i]; *s; ++s)
        {
            if(*s == '/' && n && dst[n - 1] == '/')
                continue;
            dbg_err_if(n + 1 >= sz);
            dst[n++] = *s;
        }
    }
    dst[n] = '\0';

    return 0;
err:
    return ~0;
}

/* if 'uri' starts with the alias' source prefix, write the resolved path to
   'dst' and return 0; ~0 if the alias does not apply */
static int http_try_resolv(const vhost_alias_t *alias, char *dst,
        const char *uri, size_t sz)
{
    dbg_err_if(alias == NULL);
    dbg_err_if(dst == NULL);
    dbg_err_if(uri == NULL);

    /* malformed (see http_alias_add), or the URI doesn't match */
    nop_err_if(alias->src == NULL);
    nop_err_if(strncmp(alias->src, uri, alias->srclen));

    /* if src doesn't end with a slash check that the next char in uri is a / */
    if(alias->src[alias->srclen - 1] != '/')
        nop_err_if(uri[alias->srclen] != '/');

    /* copy-out the resolved uri to dst */
    dbg_err_if(http_path_join(dst, sz, alias->dst, uri + alias->srclen));

    return 0;
err:
    return ~0;
}

vhost_list_t* http_get_vhost_list(http_t *http)
{
    dbg_err_if(http == NULL);

    return http->vhosts;
err:
    return NULL;
}

vhost_t* http_get_vhost(http_t *h, request_t *rq)
{
    const char *host;
    char *p, hostcp[128];
    vhost_t *vh = NULL;

    dbg_err_if (h == NULL);
    dbg_err_if (rq == NULL);

    if((vh = request_get_vhost(rq)) != NULL)
        return vh; /* cached */

    if((host = request_get_field_value(rq, "Host")) != NULL)
    {
        dbg_err_if(u_strlcpy(hostcp, host, sizeof(hostcp)));

        /* remove :port part */   
        if((p = strrchr(hostcp, ':')) != NULL)
            *p = 0;

        vh = vhost_list_get(h->vhosts, hostcp);
    }

    if(vh == NULL)
    {
        /* get the default vhost */
        vh = vhost_list_get_n(h->vhosts, 0);
        dbg_err_if(vh == NULL);
    }

    return vh;
err:
    return NULL;
}

/* append alias value 'v' ("src dst"), split once here instead of for every
   request; a malformed one (no value, or no dst) is kept but never matches */
static int http_alias_add(vhost_t *vhost, const char *v)
{
    static const char WP[] = " \t";
    vhost_alias_t *a = &vhost->alias[vhost->nalias];
    char *copy = NULL, *src, *dst, *pp = NULL;

    memset(a, 0, sizeof *a);
    vhost->nalias++;    /* vhost_free frees what is set below */

    if(v == NULL)
        return 0;
    dbg_err_if((copy = u_strdup(v)) == NULL);

    if((src = strtok_r(copy, WP, &pp)) == NULL ||
            (dst = strtok_r(NULL, WP, &pp)) == NULL)
    {
        warn("alias \"%s\" ignored: \"source target\" expected", v);
        U_FREE(copy);
        return 0;
    }

    dbg_err_if((a->src = u_strdup(src)) == NULL);
    dbg_err_if((a->dst = u_strdup(dst)) == NULL);
    a->srclen = strlen(src);

    U_FREE(copy);

    return 0;
err:
    U_FREE(copy);
    return ~0;
}

/* collect the vhost's dir_alias and then cgi.script_alias values once (they
 * are tried in this order for every request) */
static int http_load_aliases(vhost_t *vhost)
{
    u_config_t *config, *cgi = NULL;
    size_t n = 0;
    int i;

    /* count them */
    for(i = 0; !u_config_get_subkey_nth(vhost->config,"dir_alias", i, &config);
        ++i)
        ++n;
    if(!u_config_get_subkey(vhost->config, "cgi", &cgi))
        for(i = 0; !u_config_get_subkey_nth(cgi, "script_alias", i, &config);
            ++i)
            ++n;
    else
        cgi = NULL;

    if(n)
    {
        dbg_err_if((vhost->alias = u_zalloc(n * sizeof(vhost_alias_t)))
                == NULL);

        /* copies: the vhost owns them (vhost_free) */
        for(i = 0; !u_config_get_subkey_nth(vhost->config,"dir_alias", i,
                    &config); ++i)
            dbg_err_if(http_alias_add(vhost, u_config_get_value(config)));
        for(i = 0; cgi && !u_config_get_subkey_nth(cgi, "script_alias", i,
                    &config); ++i)
            dbg_err_if(http_alias_add(vhost, u_config_get_value(config)));
    }

    vhost->alias_loaded = 1;

    return 0;
err:
    /* drop what was copied: the next request tries again */
    while(vhost->alias && vhost->nalias)
    {
        --vhost->nalias;
        U_FREE(vhost->alias[vhost->nalias].src);
        U_FREE(vhost->alias[vhost->nalias].dst);
    }
    U_FREE(vhost->alias);
    return ~0;
}

int http_alias_resolv(http_t *h, request_t *rq, char *dst, const char *uri,
        size_t sz)
{
    vhost_t *vhost;
    size_t i;

    dbg_err_if (h == NULL);
    dbg_err_if (dst == NULL);
    dbg_err_if (uri == NULL);

    dbg_err_if((vhost = http_get_vhost(h, rq)) == NULL);

    if(!vhost->alias_loaded)
        dbg_err_if(http_load_aliases(vhost));

    /* try each dir_alias, then each script_alias */
    for(i = 0; i < vhost->nalias; ++i)
    {
        if(!http_try_resolv(&vhost->alias[i], dst, uri, sz))
            return 0;   /* alias found, uri resolved */
    }

    /* alias not found, prepend dir_root to the uri */
    dbg_err_if(http_path_join(dst, sz, vhost->dir_root, uri));

    return 0;
err:
    return ~0;
}

static int http_is_valid_uri(void *arg, const char *buf, size_t len)
{
    request_t *rq = (request_t *)arg;
    char resolved[U_FILENAME_MAX], uri[URI_MAX];
    http_t *h = NULL;

    dbg_err_if (rq == NULL);
    dbg_err_if (buf == NULL);
    dbg_err_if (len + 1 > URI_MAX);

    dbg_err_if ((h = request_get_http(rq)) == NULL);

    memcpy(uri, buf, len);
    uri[len] = '\0';
    
    /* try the url itself */
    if(broker_is_valid_uri(h->broker, h, rq, uri, strlen(uri)))
        return 1;

    /* try the path-resolved url */
    dbg_err_if(http_alias_resolv(h, rq, resolved, uri, sizeof resolved));

    return broker_is_valid_uri(h->broker, h, rq, resolved, strlen(resolved));
err:
    return 0; /* error, not a valid uri */
}

static int http_resolv_request(http_t *h, request_t *rq)
{
    const char *cstr;
    char resolved[U_FILENAME_MAX];

    dbg_err_if(h == NULL);
    dbg_err_if(rq == NULL);
    
    /* unalias rq->filename */
    if((cstr = request_get_filename(rq)) != NULL)
    {
        dbg_err_if(http_alias_resolv(h, rq, resolved, cstr, U_FILENAME_MAX));

        dbg_err_if(request_set_resolved_filename(rq, resolved));
    }

    /* unalias rq->path_info */
    if((cstr = request_get_path_info(rq)) != NULL)
    {
        dbg_err_if(http_alias_resolv(h, rq, resolved, cstr, U_FILENAME_MAX));

        dbg_err_if(request_set_resolved_path_info(rq, resolved));
    }

    return 0;
err:
    return ~0;
}

static int http_is_valid_index(http_t *h, request_t *rq, const char *uri)
{
    char resolved[U_FILENAME_MAX] = { 0 };

    dbg_err_if(http_path_join(resolved, U_FILENAME_MAX,
            request_get_resolved_filename(rq), uri));

    if(broker_is_valid_uri(h->broker, h, rq, resolved, strlen(resolved)))
        return 1; /* index found */

err:
    return 0; /* index not found */
}

static int http_get_config_index(http_t *h, request_t *rq, char *idx, size_t sz)
{
    vhost_t *vhost;
    char buf[256], *tok, *src, *pp = NULL;
    const char *cindex = NULL;

    dbg_err_if (h == NULL);
    dbg_err_if (rq == NULL);

    dbg_err_if((vhost = http_get_vhost(h, rq)) == NULL);

    /* the "index" value, read when the vhost was set up */
    if((cindex = vhost->index) == NULL)
        return ~0; /* index config key missing */

    /* copy the string (strtok_r modifies it) */
    dbg_err_if(u_strlcpy(buf, cindex, sizeof(buf)));

    for(src = buf; (tok = strtok_r(src, " \t", &pp)) != NULL; src = NULL)
    {
        if(!strcmp(tok, ""))
            continue; 

        if(http_is_valid_index(h, rq, tok))
        {
            dbg_err_if(u_strlcpy(idx, tok, sz));
            return 0; /* index page found */
        }
    }

    /* fall through */
err:
    return ~0;
}

static int http_get_default_index(http_t *h, request_t *rq, char *cindex, 
        size_t sz)
{
    const char **pg;
    static const char *indexes[] = 
    { 
        "/index.kl1",
        "/index.html", 
        "/index.htm", 
        "/index.klx", 
        "/index.klin",
        "/index.klone", /* before KLone was renamed Klin */
        "/index.klc",
        NULL 
    };

    dbg_err_if (h == NULL);
    dbg_err_if (rq == NULL);
    dbg_err_if (cindex == NULL);

    /* try to find an index page between default index uris */
    for(pg = indexes; *pg; ++pg)
    {
        if(http_is_valid_index(h, rq, *pg))
        {
            dbg_err_if(u_strlcpy(cindex, *pg, sz));
            return 0; /* index page found */
        }
    }

    /* fall through */
err:
    return ~0;
}

static int http_set_index_request(http_t *h, request_t *rq)
{
    char idx[128], uri[1024];

    dbg_err_if (h == NULL);
    dbg_err_if (rq == NULL);

    /* find an index page; try first config options then static index names */
    nop_err_if(http_get_config_index(h, rq, idx, sizeof(idx)) &&
            http_get_default_index(h, rq, idx, sizeof(idx)));

    dbg_err_if(u_snprintf(uri, sizeof(uri), "%s%s", 
                request_get_filename(rq), idx));

    dbg_if(request_set_filename(rq, uri));

    dbg_err_if(http_resolv_request(h, rq));

    return 0;
err:
    return ~0;
}

static int http_add_default_header(http_t *h, request_t *rq, response_t *rs)
{
    vhost_t *vhost;
    time_t now;

    dbg_err_if (h == NULL);
    dbg_err_if (rs == NULL);
    
    dbg_err_if((vhost = http_get_vhost(h, rq)) == NULL);

    /* set server signature */
    dbg_err_if(response_set_field(rs, "Server", vhost->server_sig));

    now = time(NULL);
    dbg_err_if(response_set_date(rs, now));

    return 0;
err:
    return ~0;
}

static int http_print_error_page(http_t *h, request_t *rq, response_t *rs, 
    int http_status)
{
    enum { BUFSZ = 64 };
    const char *err_page;
    char s[URI_MAX], *sp = NULL;
    char buf[BUFSZ], *pp = NULL;
    char page[URI_MAX + 512];
    vhost_t *vhost;
    size_t len;
    int n;

    dbg_err_if (h == NULL);
    dbg_err_if (rq == NULL);
    dbg_err_if (rs == NULL);
    dbg_err_if (http_status == 0);
    
    /* clean dirty header fields (not for redirects) */
    if(http_status != 302)
        dbg_err_if(header_clear(response_get_header(rs)));

    /* add default header fields */
    dbg_err_if(http_add_default_header(h, rq, rs));

    /* disable page caching */
    dbg_err_if(response_disable_caching(rs));

    /* looking for user provided error page */
    dbg_err_if(u_snprintf(buf, BUFSZ, "error.%d", http_status));
    if((vhost = http_get_vhost(h, rq)) == NULL)
        err_page = u_config_get_subkey_value(h->config, buf);
    else
        err_page = u_config_get_subkey_value(vhost->config, buf);

    if(err_page && !request_set_uri(rq, err_page, NULL, NULL))
    {
        dbg_err_if(http_resolv_request(h, rq));

        /* http_is_valid_uri() expects uri without parameters */
        dbg_err_if (u_strlcpy(s, err_page, sizeof s));

        sp = strtok_r(s, "?", &pp);
        dbg_err_if (sp == NULL);

        if(http_is_valid_uri(rq, sp, strlen(sp)))
        {
            /* user provided error page found */
            broker_serve(h->broker, h, rq, rs);
            return 0;
        }

        /* page not found */
        warn("%d handler page (%s) not found", http_status, sp);
    }

    /* be sure that the status code is properly set */
    response_set_status(rs, http_status);

    /* format the default error page (truncated if the URI is too long) so
       its length can be sent and the connection kept open */
    n = snprintf(page, sizeof page,
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
        "<html><head><title>%d %s</title></head>\n"
        "<body><h1>%s</h1><p>URL: %s</p><hr>"
        "<address>Klin/%s web server</address>"
        "</body></html>",
        http_status, http_get_status_desc(http_status),
        http_get_status_desc(http_status),
        (request_get_uri(rq) ? request_get_uri(rq) : ""),
        KLIN_VERSION);
    dbg_err_if(n < 0);
    len = U_MIN((size_t) n, sizeof page - 1);

    dbg_err_if(response_set_content_length(rs, len));

    response_print_header(rs);

    if(request_get_method(rq) == HM_HEAD)
        return 0; /* just the header is requested */

    /* print default error page */
    dbg_err_if(io_write(response_io(rs), page, len) < 0);

    return 0;
err:
    return ~0;
}

/* local and peer address of a connection, set into each of its requests */
typedef struct http_conn_addr_s
{
    char local[128];
    char peer[128];
} http_conn_addr_t;

static int http_get_conn_addr(int fd, int cgi, http_conn_addr_t *ca)
{
    struct sockaddr_storage ss;
    socklen_t slen;
    const char *port;

    dbg_err_if (ca == NULL);

    ca->local[0] = ca->peer[0] = '\0';

    if (cgi)
    {
        /* the client is the peer, the web server running us the local end
           (these were swapped) */
        if (getenv("REMOTE_ADDR") && getenv("REMOTE_PORT"))
            (void) u_addr_fmt(getenv("REMOTE_ADDR"), getenv("REMOTE_PORT"),
                    ca->peer, sizeof ca->peer);

        if (getenv("SERVER_ADDR"))
        {
            if ((port = getenv("SERVER_PORT")) == NULL)
                port = "80";

            (void) u_addr_fmt(getenv("SERVER_ADDR"), port, ca->local,
                    sizeof ca->local);
        }
    }
    else
    {
        slen = sizeof ss;

        /* set local addr */
        dbg_err_if(getsockname(fd, (struct sockaddr *) &ss, &slen) == -1);
        dbg_err_if(u_sa_ntop((struct sockaddr *) &ss, ca->local,
                    sizeof ca->local) == NULL);

        /* set peer addr */
        slen = sizeof ss;
        dbg_err_if(getpeername(fd, (struct sockaddr *) &ss, &slen) == -1);
        dbg_err_if(u_sa_ntop((struct sockaddr *) &ss, ca->peer,
                    sizeof ca->peer) == NULL);
    }

    return 0;
err:
    return ~0;
}

/* complete the response (the codecs, e.g. the response filter, print what
 * they hold) and tell if the connection can serve another request */
static int http_end_response(io_t *out, request_t *rq, response_t *rs)
{
    int keep;

    /* a response may not have written a byte yet (e.g. HEAD, empty page):
       the write buffer must exist for the codecs to be flushed */
    keep = (io_write(out, "", 0) == 0);

    keep = (io_codecs_remove(out) == 0) && keep;
    keep = (io_flush(out) == 0) && keep;

    /* the response must be complete and delimited, and the unread part of
     * the request body skipped */
    return keep && response_get_keep_alive(rs) &&
        request_drain_body(rq, HTTP_KEEP_ALIVE_DRAIN_MAX) == 0;
}

/* serve one request read from 'cin' writing the response to 'cout' (the
 * same io_t but in CGI mode); on return *keep is !0 if the connection can
 * be used for another request */
static int http_serve_request(http_t *h, io_t *cin, io_t *cout, int cgi,
        const http_conn_addr_t *ca, int nreq, int keep_alive, int *keep)
{
    request_t *rq = NULL;
    response_t *rs = NULL;
    io_t *in = NULL, *out = NULL;
    int rc = HTTP_STATUS_INTERNAL_SERVER_ERROR, committed, hooked = 0;
    const char *cstr, *proto;
    vhost_t *vhost;
    const char *uri;
    char nuri[URI_MAX];
    supplier_t *sup;

    dbg_err_if (h == NULL);
    dbg_err_if (cin == NULL);
    dbg_err_if (cout == NULL);
    dbg_err_if (keep == NULL);

    *keep = 0;

    /* create a request object */
    dbg_err_if(request_create(h, &rq));
    request_set_cgi(rq, cgi);

    /* on a kept-alive connection wait for the next request a shorter time */
    if(nreq)
        request_set_keep_alive_wait(rq, h->ka_timeout);

    /* save local and peer address into the request object */
    if(ca->local[0])
        dbg_err_if(request_set_addr(rq, ca->local));
    if(ca->peer[0])
        dbg_err_if(request_set_peer_addr(rq, ca->peer));

    /* bind the request object to the connection */
    dbg_err_if(io_dup(cin, &in));
    dbg_err_if(request_bind(rq, in));
    in = NULL;

    /* create a response object */
    dbg_err_if(response_create(h, &rs));

    response_set_cgi(rs, cgi);

    if(cgi)
        dbg_err_if(cgi_set_request(rq));

    /* default method used if we cannot parse the request (bad request) */
    response_set_method(rs, HM_GET);

    /* bind the response to the connection */
    dbg_err_if(io_dup(cout, &out));
    dbg_err_if(response_bind(rs, out));
    out = NULL;

    /* server ready, parse the request */
    dbg_err_if(response_set_status(rs, HTTP_STATUS_BAD_REQUEST));
    rc = HTTP_STATUS_BAD_REQUEST;

    /* parse request. may fail on timeout */
    if(request_parse_header(rq, http_is_valid_uri, rq))
    {
        /* the client closed (or left idle) the connection: nothing to do */
        if(request_conn_closed(rq))
            goto end;
        goto err;
    }

    /* busy again after waiting on a kept-alive connection */
    if(nreq)
        dbg_if(server_watchdog(ctx->server, 1));

    response_set_method(rs, request_get_method(rq));

    /* keep the connection open if both sides want it */
    proto = request_get_protocol(rq);    /* NULL in CGI mode */
    response_set_keep_alive(rs, keep_alive && request_keep_alive(rq),
            proto && !strcmp(proto, "HTTP/1.1"));

    /* get and cache the vhost ptr to speed up next lookups */
    dbg_err_if((vhost = http_get_vhost(h, rq)) == NULL);
    request_set_vhost(rq, vhost);

    /* if we're running in server mode then resolv aliases and dir_root */
    dbg_err_if(http_resolv_request(h, rq));

    /* if the uri end with a slash then return an index page */
    request_get_sup_info(rq, &sup, NULL, NULL);
    if(sup == NULL && (cstr = request_get_filename(rq)) != NULL &&
            cstr[strlen(cstr)-1] == '/')
        dbg_if(http_set_index_request(h, rq)); /* set the index page */

    /* add default header fields */
    dbg_err_if(http_add_default_header(h, rq, rs));

    /* set default successfull status code */
    dbg_err_if(response_set_status(rs, HTTP_STATUS_OK));

    /* serve the page; on error write out a simple error page */
    rc = broker_serve(h->broker, h, rq, rs);

    /* on 404 (file not found) try to find out if this is a directory request
       i.e. http://site:port/dir redirects to /dir/ */
    if(response_get_status(rs) == 404 && (uri = request_get_uri(rq)) != NULL &&
            uri[strlen(uri)-1] != '/')
    {
        if(!http_set_index_request(h, rq))
        {
            (void) u_strlcpy(nuri, request_get_uri(rq), sizeof(nuri));
            (void) u_strlcat(nuri, "/", sizeof(nuri));

            if(request_get_path_info(rq))
                (void) u_strlcat(nuri, request_get_path_info(rq), sizeof(nuri));

            if(request_get_query_string(rq))
            {
                (void) u_strlcat(nuri, "?", sizeof(nuri));
                (void) u_strlcat(nuri, request_get_query_string(rq),
                        sizeof(nuri));
            }

            response_redirect(rs, nuri);
            rc = HTTP_STATUS_MOVED_TEMPORARILY;
        }
    }

    /* log the request */
    if(vhost->klog)
        dbg_if(access_log(h, vhost->al_config, rq, rs));

    /* call the hook that fires on each request */
    hook_call(request, rq, rs);
    hooked = 1;

    /* on broker_serve error jump to err */
    nop_err_if(rc != 0);

    /* page successfully served */
    *keep = http_end_response(cout, rq, rs);

    request_free(rq);
    response_free(rs); /* must be free'd after the request object because
                          the rsfilter references the response object during
                          the flush of the codec (so the response object must
                          not be free'd) that happens during the io_free call */
    return 0;
err:
    /* hook get fired also on error, once (a redirect or a failed page has
       been through it already) */
    if(rq && rs && !hooked)
        hook_call(request, rq, rs);

    if(rc && rq && rs && response_io(rs))
    {
        if(!(committed = response_header_sent(rs)))
        {
            /* drop what the failed page left in the codecs (e.g. output 
               buffered by the response filter) and print the error page */
            dbg_if(io_codecs_discard(cout));
            http_print_error_page(h, rq, rs, rc);
        }

        /* after a partial response the connection must be closed */
        *keep = http_end_response(cout, rq, rs) && !committed;
    }
end:
    if(in)
        io_free(in);
    if(out)
        io_free(out);
    if(rq)
        request_free(rq);
    if(rs)
        response_free(rs);
    return ~0;
}

static int http_serve(http_t *h, int fd, int keep_alive)
{
    io_t *conn = NULL, *cout = NULL;
    http_conn_addr_t ca;
    const char *gwi = NULL;
    int cgi = 0, nreq, keep = 0, owned = 1;   /* fd is ours to close */

    dbg_err_if (h == NULL);
    dbg_err_if (fd < 0);

    if(fd == 0 && (gwi = getenv("GATEWAY_INTERFACE")) != NULL)
        cgi++; /* klin is being used as a CGI */

    /* the web server running the CGI owns the connection */
    if(cgi || !h->keep_alive)
        keep_alive = 0;

    dbg_err_if(http_get_conn_addr(fd, cgi, &ca));

    /* from here the connection io closes fd (also when its creation fails,
       e.g. on a failed TLS handshake) */
    owned = 0;

#ifdef SSL_ON
    /* create the connection io (the TLS handshake happens here) */
    if(h->ssl && !cgi)
        dbg_err_if(io_ssl_create(fd, IO_FD_CLOSE, 0, h->ssl_ctx, &conn));
    else
        dbg_err_if(io_fd_create(fd, IO_FD_CLOSE, &conn));
#else
    /* create the connection io */
    dbg_err_if(io_fd_create(fd, IO_FD_CLOSE, &conn));
#endif

    /* write large responses in large blocks: 4 KB writes are several times
       slower (more system calls, partial TCP segments) */
    dbg_err_if(io_set_write_buffer_size(conn, HTTP_CONN_WBUFSZ));

    /* the response goes to the same connection, or to stdout for a CGI */
    if(cgi)
        dbg_err_if(io_fd_create(1, IO_FD_CLOSE, &cout));
    else {
        dbg_err_if(io_dup(conn, &cout));

        /* the codecs of the shared connection belong to the response: 
           reading the request (body) must bypass them */
        io_set_write_codecs(conn, 1);
    }

    /* serve requests until the client or the server closes the connection */
    for(nreq = 0; nreq < h->ka_max; ++nreq)
    {
        (void) http_serve_request(h, conn, cout, cgi, &ca, nreq,
                keep_alive && nreq + 1 < h->ka_max, &keep);
        if(!keep)
            break;

        /* waiting for the next request is not a slow page (prefork) */
        dbg_if(server_watchdog(ctx->server, 0));
    }

    io_free(cout);
    io_free(conn);

    return 0;
err:
    if(cout)
        io_free(cout);
    if(conn)
        io_free(conn);
    if(owned && fd >= 0)
        close(fd);
    return ~0;
}

static int http_free(http_t *h)
{
    dbg_return_if (h == NULL, 0);   /* it's ok */

    if(h->broker)
        broker_free(h->broker);

    if(h->vhosts)
        vhost_list_free(h->vhosts);

    U_FREE(h);

    return 0;
}

static int http_add_vhost(http_t *http, const char *host, u_config_t *c)
{
    vhost_t *top, *vhost = NULL;
    u_config_t *child;
    const char *v;

    dbg_err_if (http == NULL);
    dbg_err_if (host == NULL);
    dbg_err_if (c == NULL);

    dbg_err_if(vhost_create(&vhost));
    
    vhost->host = host;
    vhost->config = c;
    vhost->http = http;

    /* set defaults */
    vhost->server_sig = "klin/" KLIN_VERSION;
    vhost->dir_root = "";
    vhost->index = NULL;
    vhost->send_enc_deflate = 0; 

    /* if there's a per-vhost access_log open it, otherwise inherit from the
       main server configuration */
    if((child = u_config_get_child(c, "access_log")) != NULL)
    {
        v = u_config_get_value(child);

        /* if the access_log key is not "no" then load the log configuration */
        if(v == NULL || strcasecmp(v, "no"))
            dbg_err_if(klog_open_from_config(child, &vhost->klog));

        vhost->al_config = child;
    } else {
        /* if there's a global access log use it */
        if((top = vhost_list_get_n(http->vhosts, 0)) != NULL)
        {
            /* inherit from the main config (may be NULL) */
            vhost->klog = top->klog;
            vhost->al_config = top->al_config;
        }
    }

    /* send_enc_deflate (disable if not configured) */
    dbg_err_if(u_config_get_subkey_value_b(c, "send_enc_deflate", 0, 
        &vhost->send_enc_deflate));

    /* server signature */
    if((v = u_config_get_subkey_value(c, "server_sig")) != NULL)
        vhost->server_sig = v;

    /* html dir root */
    if((v = u_config_get_subkey_value(c, "dir_root")) != NULL)
        vhost->dir_root = v;
    else
        crit_err("dir_root must be set (vhost: %s)", vhost->host);

    /* index page */
    if((v = u_config_get_subkey_value(c, "index")) != NULL)
        vhost->index = v;

    dbg_err_if(vhost_list_add(http->vhosts, vhost));

    return 0;
err:
    if(vhost)
        vhost_free(vhost);
    return ~0;
}

static int config_inherit(u_config_t *dst, u_config_t *from)
{
    static const char *dont_inherit[] = {
        "addr", "model", "type", "dir_root", "dir_alias", "script_alias", 
        "access_log", NULL
    };
    u_config_t *config, *child = NULL;
    const char **di, *key, *value;
    int n;

    dbg_err_if (dst == NULL);
    dbg_err_if (from == NULL);

    for(n = 0; (config = u_config_get_child_n(from, NULL, n)); ++n)
    {
        if(u_config_get_child(config, "dir_root"))
            continue; /* skip vhost config subtree */
        
        key = u_config_get_key(config);
        value = u_config_get_value(config);

        /* don't inherit keys listed in dont_inherit array */
        for(di = dont_inherit; *di; ++di)
            if(strcasecmp(*di, key) == 0)
                goto next;

        dbg_err_if(u_config_add_child(dst, key, &child));
        dbg_err_if(u_config_set_value(child, value));

        dbg_err_if(config_inherit(child, config));

    next:;
    }

    return 0;
err:
    return ~0;
}

static int http_set_vhost_list(http_t *http)
{
    u_config_t *config;
    int n;

    dbg_err_if (http == NULL);

    /* virtual vhost that stores the main server config */
    dbg_err_if(http_add_vhost(http, "", http->config));

    /* look for vhosts (any key that contain a dir_root subkey is a vhost) */
    for(n = 0; (config = u_config_get_child_n(http->config, NULL, n)); ++n)
    {
        if(u_config_get_child(config, "dir_root") == NULL)
            continue; /* it's not a vhost config branch */

        dbg_err_if(u_config_get_key(config) == NULL);

        u_info("configuring virtual host [%s]", u_config_get_key(config));

        /* inherit top-level values */
        dbg_err_if(config_inherit(config, http->config));

        dbg_err_if(http_add_vhost(http, u_config_get_key(config), config));
    }

    return 0;
err:
    return ~0;
}

static int http_create(u_config_t *config, http_t **ph)
{
    http_t *h = NULL;

    dbg_err_if (config == NULL);
    dbg_err_if (ph == NULL);

    h = u_zalloc(sizeof(http_t));
    dbg_err_if(h == NULL);

    h->config = config;

    /* persistent connections */
    dbg_err_if(u_config_get_subkey_value_b(config, "keep_alive", 1,
                &h->keep_alive));
    dbg_err_if(u_config_get_subkey_value_i(config, "keep_alive_timeout",
                HTTP_KEEP_ALIVE_TIMEOUT, &h->ka_timeout));
    dbg_err_if(u_config_get_subkey_value_i(config, "keep_alive_max",
                HTTP_KEEP_ALIVE_MAX, &h->ka_max));
    h->ka_timeout = U_MAX(1, h->ka_timeout);
    h->ka_max = U_MAX(1, h->ka_max);

    dbg_err_if(vhost_list_create(&h->vhosts));

    /* init page broker (and page suppliers) */
    dbg_err_if(broker_create(&h->broker));

    /* load main server and vhosts config */
    dbg_err_if(http_set_vhost_list(h));

    /* print-out config with inherited values */
    if(ctx->debug > 1)
        u_config_print(ctx->config, 0);

    *ph = h;

    return 0;
err:
    if(h)
        http_free(h);
    return ~0;
}

static int http_backend_serve(struct backend_s *be, int fd)
{
    http_t *h;
    int rc;

    dbg_err_if (be == NULL);
    dbg_err_if (be->arg == NULL);
    dbg_err_if (fd < 0);
    
    h = (http_t *) be->arg;
    
    /* new connection accepted on http listening socket, handle it; in the
     * iterative model an idle kept-alive client would block the server */
    rc = http_serve(h, fd, be->model != SERVER_MODEL_ITERATIVE);

    return rc;
err:
    if(fd >= 0)
        close(fd);
    return ~0;
}

static int http_backend_term(struct backend_s *be)
{
    http_t *http;

    dbg_return_if (be == NULL, 0);
    dbg_return_if (be->arg == NULL, 0);

    http = (http_t *) be->arg;

    dbg_err_if(session_module_term(http->sess_opt));

    http_free(http);

    return 0;
err:
    return ~0;
}

static int http_backend_init(struct backend_s *be)
{
    http_t *http = NULL;
    broker_t *broker = NULL;

    dbg_err_if (be == NULL);
 
    dbg_err_if(http_create(be->config, &http));

    be->arg = http;

    dbg_err_if(session_module_init(http->config, &http->sess_opt));

    return 0;
err:
    if(http)
        http_free(http);
    if(broker)
        broker_free(broker);
    return ~0;
}

#ifdef SSL_ON
static int https_backend_init(struct backend_s *be)
{
    http_t *https;

    dbg_err_if (be == NULL);

    dbg_err_if(http_backend_init(be));

    https = (http_t *) be->arg;

    /* turn on SSL encryption */
    https->ssl = 1;

    /* load config values and set SSL_CTX accordingly */
    https->ssl_ctx = tls_load_init_ctx(http_get_config(https));
    warn_err_ifm (https->ssl_ctx == NULL, "bad or missing HTTPS credentials");

    /* session options were already loaded by http_backend_init() */

    return 0;
err:
    return ~0;
}

static int https_backend_term(struct backend_s *be)
{
    http_t *https;

    dbg_err_if (be == NULL);

    https = (http_t *) be->arg;
    if (https == NULL)
        return 0;

    SSL_CTX_free(https->ssl_ctx);

    return http_backend_term(be); 
err:
    return ~0;
}

/* same http functions but different '_init' */
backend_t be_https =
    BACKEND_STATIC_INITIALIZER( "https", 
        https_backend_init, 
        http_backend_serve, 
        https_backend_term );
#endif /* SSL_ON */

backend_t be_http =
    BACKEND_STATIC_INITIALIZER( "http", 
        http_backend_init, 
        http_backend_serve, 
        http_backend_term );

