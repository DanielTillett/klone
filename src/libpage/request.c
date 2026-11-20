/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <klin/json.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <u/libu.h>
#include <klin/request.h>
#include <klin/utils.h>
#include <klin/io.h>
#include <klin/ioprv.h>
#include <klin/http.h>
#include <klin/vars.h>
#include <klin/timer.h>
#include <klin/vhost.h>
#include <klin/supplier.h>

struct request_s
{
    http_t *http;               /* http server handle                       */
    header_t *header;           /* input header                             */
    io_t *io;                   /* input io stream                          */
    int method;                 /* get,post,etc.                            */
    char *cli_rq;               /* verbatim client request line             */
    char *uri;                  /* verbatim uri asked by the client         */
    char *protocol;             /* proto/ver                                */
    char *path_info;            /* extra info at the end of the path        */
    char *query;                /* query string (data after '?')            */
    char *filename;             /* path of the req resource                 */
    char *resolved_path_info;   /* resolved path_info                       */
    char *resolved_filename;    /* unaliased filename                       */
    vars_t *args;               /* mixed get/post args                      */
    vars_t *args_get;           /* get variables                            */
    vars_t *args_post;          /* post variables                           */
    vars_t *cookies;            /* cookies                                  */
    vars_t *uploads;            /* uploaded file list                       */
    char *content_type;         /* type/subtype                             */
    char *content_encoding;     /* 7bit/8bit/base64/qp, etc                 */
	size_t content_length;      /* content-length http header field         */
    time_t if_modified_since;   /* time_t IMS header                        */
    int cgi;                    /* if running in cgi mode                   */
    size_t idle_timeout;        /* max # of secs to wait for the request    */
    size_t post_timeout;        /* max # of secs for reading POSTed data    */
    size_t post_maxsize;        /* max # of POSTed bytes to accepts         */
    const char *temp_dir;       /* where temp files go                      */
    vhost_t *vhost;             /* cached vhost pointer                     */
    size_t padding;
    /* cached supplier info data */
    supplier_t *si_sup;
    void *si_handle;
    time_t si_mtime;
    size_t body_off;
    /* persistent connections */
    size_t hdr_end;             /* stream offset of the end of the header   */
    int ka_wait;                /* waiting on a kept-alive connection       */
    int conn_closed;            /* closed or idle before any request byte   */
    int parse_status;           /* why request_parse_header() failed        */
    size_t max_fields;          /* header limits (request_parse_header)     */
    size_t max_line, max_header;
    /* HTTP authentication (see auth.c): the realm the path is in, the user
       who authenticated (both in the configuration), a stale nonce */
    const char *auth_user;
    void *auth_realm;
    int auth_stale;
    vars_t *route_params;       /* {name} values of a matched route       */
    int data_parsed;            /* request_parse_data() has run ...       */
    int data_rc;                /* ... and returned this                  */

    /* strings, last: request_create() does not zero them */
    char local_addr[256];       /* local address                            */
    char peer_addr[256];        /* peer address                             */
};

typedef struct upload_info_s    /* uploaded file info struct         */
{
    char mime_type[MIME_TYPE_BUFSZ];
    char filename[U_FILENAME_MAX];
    size_t size;
} upload_info_t;

enum { 
    REQUEST_DEFAULT_IDLE_TIMEOUT = 10,         /* 10 secs */
    REQUEST_DEFAULT_POST_TIMEOUT = 600,        /* 10 mins */
    REQUEST_DEFAULT_POST_MAXSIZE = 5*1024000,  /* 5 MB    */
    REQUEST_DEFAULT_MAX_FIELDS = 100,          /* header fields           */
    REQUEST_DEFAULT_MAX_LINE = 8192,           /* bytes in one field      */
    REQUEST_DEFAULT_MAX_HEADER = 32768,        /* bytes in the header     */
    REQUEST_LINE_MAX = 8192,                   /* bytes in the request line */
};


#define REQUEST_SET_STRING_FIELD(lval, rval)        \
    do {                                            \
        U_FREE(lval);                               \
        if(rval)                                    \
        {                                           \
            lval = u_strdup(rval);                  \
            dbg_err_if(lval == NULL);               \
        }                                           \
    } while(0)


int request_is_encoding_accepted(request_t *rq, const char *encoding)
{
    char *pp, *tok, *src, *buf = NULL;
    const char *accept_encoding;
    int rc = 0;

    dbg_err_if (rq == NULL);
    dbg_err_if (encoding == NULL);
    
    accept_encoding = header_get_field_value(rq->header, "Accept-Encoding");
    if(accept_encoding)
    {
        /* get a copy to work on */
        buf = u_strdup(accept_encoding);
        dbg_err_if(buf == NULL);

        /* foreach encoding pair... */
        for(src = buf; (tok = strtok_r(src, " ,", &pp)) != NULL; src = NULL)
        {
            if(strcasecmp(tok, encoding) == 0)
            {
                rc++; /* found */
                break;
            }
        }

        U_FREE(buf);
    }

    return rc;
err:
    U_FREE(buf);
    return 0;
}

/**
 * \ingroup request
 * \brief   Get the \c io_t object associated with a request object
 *
 * Return the I/O object (\c io_t) used by the request object passed as 
 * parameter.  The \c io_t object is bound to the socket connected to the
 * client (the web browser).
 *
 * \param rq    request object
 *
 * \return child \c io_t object of the given \p rq or NULL if no \c io_t 
 *         object has been set
 *
 * \sa io_t
 */
io_t *request_io(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->io;
}

/* the variable lists are created on first use: most requests (e.g. for
 * static files) have no arguments, cookies or uploads */
static vars_t *request_vars(request_t *rq, vars_t **pvars)
{
    if(*pvars == NULL)
    {
        dbg_err_if(vars_create(pvars));

        /* args_get and args_post link to var_t owned by the rq->args list */
        if(pvars == &rq->args_get || pvars == &rq->args_post)
            dbg_err_if(vars_set_flags(*pvars, VARS_FLAG_FOREIGN));
    }

    return *pvars;
err:
    if(*pvars)
    {
        vars_free(*pvars);
        *pvars = NULL;
    }
    return NULL;
}

/**
 * \ingroup request
 * \brief   Get the cookies list
 *
 * Return a \c vars_t object containing the list of all cookies sent by the
 * browser.
 *
 * \param rq  request object
 *
 * \return the cookie list of the given \p rq
 */
vars_t *request_get_cookies(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return request_vars(rq, &rq->cookies);
}

/**
 * \ingroup request
 * \brief   Get the value of a cookie named \p name
 *
 * Return the value of a cookie sent by the browser
 *
 * \param rq    request object
 * \param name  cookie name
 *
 * \return the cookie value or \c NULL on error
 */
const char *request_get_cookie(request_t *rq, const char *name)
{
    var_t *v;

    dbg_return_if (rq == NULL, NULL);
    dbg_return_if (name == NULL, NULL);

    v = vars_get(request_vars(rq, &rq->cookies), name);

    return v ? var_get_value(v): NULL;
}

/**
 * \ingroup request
 * \brief   Get the list of request variables (using either GET or POST method)
 *
 * Return get/post arguments of request \p rq in a \c vars_t object
 *
 * \param rq  request object
 *
 * \return the arguments' list of the given \p rq
 */
vars_t *request_get_args(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return request_vars(rq, &rq->args);
}

/**
 * \ingroup request
 * \brief   Get request variables passed using the GET method
 *
 * Return GET arguments of request \p rq in a \c vars_t object
 *
 * \param rq  request object
 *
 * \return the arguments' list of the given \p rq
 */
vars_t *request_get_getargs(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return request_vars(rq, &rq->args_get);
}

/**
 * \ingroup request
 * \brief   Get request variables passed using the POST method
 *
 * Return POST arguments of request \p rq in a \c vars_t object
 *
 * \param rq  request object
 *
 * \return the arguments' list of the given \p rq
 */
vars_t *request_get_postargs(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return request_vars(rq, &rq->args_post);
}

/**
 * \ingroup request
 * \brief   Get a request variable (using either GET or POST variable list)
 *
 * Return the string value of argument \p name in request \p rq.
 *
 * \param rq    request object
 * \param name  name of the argument
 *
 * \return
 *  - the string value corresponding to the supplied \p name 
 *  - \c NULL if there's no argument named \p name
 */
const char *request_get_arg(request_t *rq, const char *name)
{
    var_t *v;

    dbg_return_if (rq == NULL, NULL);
    dbg_return_if (name == NULL, NULL);

    v = vars_get(request_vars(rq, &rq->args), name);

    return v ? var_get_value(v): NULL;
}

/**
 * \ingroup request
 * \brief   Return a GET variable
 *
 * Return the string value of argument \p name in request \p rq.
 *
 * \param rq    request object
 * \param name  name of the argument
 *
 * \return
 *  - the string value corresponding to the supplied \p name 
 *  - \c NULL if there's no argument named \p name
 */
const char *request_get_getarg(request_t *rq, const char *name)
{
    var_t *v;

    dbg_return_if (rq == NULL, NULL);
    dbg_return_if (name == NULL, NULL);

    v = vars_get(request_vars(rq, &rq->args_get), name);

    return v ? var_get_value(v): NULL;
}

/**
 * \ingroup request
 * \brief   Return a POST variable
 *
 * Return the string value of argument \p name in request \p rq.
 *
 * \param rq    request object
 * \param name  name of the argument
 *
 * \return
 *  - the string value corresponding to the supplied \p name 
 *  - \c NULL if there's no argument named \p name
 */
const char *request_get_postarg(request_t *rq, const char *name)
{
    var_t *v;

    dbg_return_if (rq == NULL, NULL);
    dbg_return_if (name == NULL, NULL);

    v = vars_get(request_vars(rq, &rq->args_post), name);

    return v ? var_get_value(v): NULL;
}

int request_set_field(request_t *rq, const char *name, const char *value)
{
    dbg_return_if (rq == NULL, ~0);
    dbg_return_if (name == NULL, ~0);
    dbg_return_if (value == NULL, ~0);

    return header_set_field(rq->header, name, value);
}

/** 
 * \ingroup request
 * \brief   Get the URI field of a request
 *  
 * Return the string value of the URI in request \p rq.
 *
 * \param rq    request object
 *  
 * \return the URI child object of the given \p rq
 */
const char *request_get_uri(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->uri;
}

/** 
 * \ingroup request
 * \brief   Get the filename field of a request
 *  
 * Return the string value of the filename field in request \p rq.
 *
 * \param rq    request object
 *  
 * \return the file name bound to \p rq (can be \c NULL) 
 */
const char *request_get_filename(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->filename;
}

/*
 * \ingroup request
 * \brief   Set the filename field of a request
 *
 * Set the filename field of request \p rq to \p filename.
 *
 * \param rq        request object
 * \param filename  filename string
 *
 * \return \c 0 if successful, non-zero on error
 */
int request_set_filename(request_t *rq, const char *filename)
{
    dbg_err_if (rq == NULL);
    dbg_err_if (filename == NULL);
    
    REQUEST_SET_STRING_FIELD(rq->filename, filename);

    return 0;
err:
    return ~0;
}

/** 
 * \ingroup request
 * \brief   Get the query string field of a request
 *  
 * Return the query string field of request \p rq.
 *
 * \param rq    request object
 *  
 * \return the query string bound to \p rq (may be \c NULL)
 */
const char *request_get_query_string(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->query;
}

/** 
 * \ingroup request
 * \brief   Get the path info field of a request
 *  
 * Return the path info field of request \p rq.
 *
 * \param rq    request object
 *  
 * \return the path info of \p rq (may be \c NULL)
 */
const char *request_get_path_info(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->path_info;
}

/* parse and set if-modified-since value */
static int request_parse_ims(request_t *rq)
{
    const char *ims;

    dbg_err_if (rq == NULL);
    
    rq->if_modified_since = 0;

    ims = header_get_field_value(rq->header, "If-Modified-Since");
    if(ims)
        dbg_err_if(u_httpdate_to_tt(ims, &rq->if_modified_since));

err: /* ignore if it's not formatted properly */
    return 0;
}

/**
 * \ingroup request
 * \brief   Get IMS field of a request
 *
 * Return the \c time_t value of the IMS field of request \p rq
 *
 * \param rq      request object
 *
 * \return a valid \c time_t value on success, \c -1 on failure
 */
time_t request_get_if_modified_since(request_t *rq)
{
    dbg_return_if (rq == NULL, (time_t) -1);

    return rq->if_modified_since;
}

/*
 * \ingroup request
 * \brief   Set the resolved filename field of a request
 *
 * Set the resolved filename field of request \p rq to \p resolved_fn
 *
 * \param rq          request object
 * \param resolved_fn resolved filename
 *
 * \return \c 0 if successful, non-zero on error
 */
int request_set_resolved_filename(request_t *rq, const char *resolved_fn)
{
    dbg_err_if (rq == NULL);
    dbg_err_if (resolved_fn == NULL);

    REQUEST_SET_STRING_FIELD(rq->resolved_filename, resolved_fn);

    return 0;
err:
    return ~0;
}

/** 
 * \ingroup request
 * \brief   Get the HTTP server handle of a request
 *  
 * Get the \c http_t object containing the HTTP server handle of request \p rq
 *
 * \param rq    request object
 *  
 * \return the child HTTP object of the given \p rq (may be \c NULL)
 */
http_t* request_get_http(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->http;
}

/*
 * \ingroup request
 * \brief   Bind request I/O to a given I/O. 
 *  
 * Bind the I/O of request \p rq to \p in.
 *
 * \param rq    request object
 * \param in    input I/O object
 *
 * \return \c 0 if successful, non-zero on error
 */
int request_bind(request_t *rq, io_t *in)
{
    dbg_return_if (rq == NULL, ~0);
    dbg_return_if (in == NULL, ~0);

    rq->io = in;

    return 0;
}

/*
 * \ingroup request
 * \brief   Set the query string of a request
 *
 * Parse \p query string and build the \p rq->args list.
 *
 * \param rq     request object
 * \param query  query string 
 *
 * \return \c 0 if successful, non-zero on error
 */
int request_set_query_string(request_t *rq, const char *query)
{
    dbg_err_if (rq == NULL);
    dbg_err_if (query == NULL);
    
    REQUEST_SET_STRING_FIELD(rq->query, query);

    return 0;
err:
    return ~0;
}

void request_clear_uri(request_t *rq)
{
    U_FREE(rq->uri);
    U_FREE(rq->protocol);
    U_FREE(rq->path_info);
    U_FREE(rq->query);
    U_FREE(rq->filename);
    U_FREE(rq->resolved_path_info);
    U_FREE(rq->resolved_filename);
    U_FREE(rq->content_type);
    U_FREE(rq->content_encoding);
}

/*
 * \ingroup request
 * \brief   Set the path info field of a request
 *
 * Set the path info field of request \p rq to \p path_info.
 *
 * \param rq         request object
 * \param path_info  path info
 *
 * \return \c 0 if successful, non-zero on error
 */
int request_set_path_info(request_t *rq, const char *path_info)
{
    dbg_err_if (rq == NULL);
    dbg_err_if (path_info == NULL);

    REQUEST_SET_STRING_FIELD(rq->path_info, path_info);

    return 0;
err:
    return ~0;
}

/*
 * \ingroup request
 * \brief   Set the resolved path info field of a request
 *
 * Set the resolved path info field of request \p rq to \p resolved_pi.
 *
 * \param rq           request object
 * \param resolved_pi  resolved path info
 *
 * \return \c 0 if successful, non-zero on error
 */
int request_set_resolved_path_info(request_t *rq, const char *resolved_pi)
{
    dbg_err_if (rq == NULL);
    dbg_err_if (resolved_pi == NULL);

    REQUEST_SET_STRING_FIELD(rq->resolved_path_info, resolved_pi);

    return 0;
err:
    return ~0;
}

/* set the filename and the path info from the URI's path: decoded,
 * normalized, and split where is_valid_uri() finds a page */
static int request_split_uri(request_t *rq,
        int (*is_valid_uri)(void*, const char *, size_t), void* arg)
{
    char *p, *fn, *pi;
    size_t uri_len, path_len;
    ssize_t decoded;
    char cp[4096];

    dbg_err_if (rq == NULL || rq->uri == NULL);

    uri_len = strlen(rq->uri);
    dbg_err_if(uri_len >= sizeof(cp));

    U_FREE(rq->path_info);
    U_FREE(rq->filename);
    U_FREE(rq->resolved_path_info);
    U_FREE(rq->resolved_filename);
    request_set_sup_info(rq, NULL, NULL, 0);

    /* Split before decoding, so %3f remains part of the path. A '+' in a
     * URI path is literal; form/query decoding has different rules. */
    p = strchr(rq->uri, '?');
    path_len = p ? (size_t)(p - rq->uri) : uri_len;
    dbg_err_if((decoded = u_urlncpy_s(cp, sizeof(cp), rq->uri, path_len, URLCPY_DECODE)) <= 0);
    dbg_err_if(memchr(cp, '\0', (size_t)decoded) != NULL);
    /* Restore literal '+' characters changed by the form decoder. */
    {
        size_t src, dst = 0;
        for (src = 0; src < path_len; ++src, ++dst)
        {
            if (rq->uri[src] == '%')
                src += 2;
            else if (rq->uri[src] == '+')
                cp[dst] = '+';
        }
    }

    /* normalize the URI (remove /../, /./, ecc) */
    dbg_err_if(u_uri_normalize(cp));

    /* look for path_info */
    fn = cp;                    /* filename     */
    pi = fn + strlen(fn);       /* path_info    */
    for(;;)
    {
        if(is_valid_uri == NULL || is_valid_uri(arg, fn, pi - fn))
        {
            if(*pi)
                dbg_err_if(request_set_path_info(rq, pi));
            *pi = 0; /* trunc */
            break;
        } else {
            /* file pointed by this uri does not exists: the filename is the
               whole path (fn is untouched), with no path_info */
            if((p = u_strnrchr(fn, '/', pi - fn)) == NULL)
                break;
            pi = p; /* try again */
        }
    }

    /* set once, when it is known */
    dbg_err_if(request_set_filename(rq, fn));

    return 0;
err:
    return ~0;
}

/*
 * \ingroup request
 * \brief   Set the URI field of a request
 *
 * Set the URI field of request \p rq to \p uri given
 *
 * \param rq           request object
 * \param uri          URI string
 * \param is_valid_uri URI validation function
 * \param arg          argument to is_valid_uri
 *
 * \return \c 0 if successful, non-zero on error
 */
int request_set_uri(request_t *rq, const char *uri,
        int (*is_valid_uri)(void*, const char *, size_t),
        void* arg)
{
    char *p;

    dbg_err_if (rq == NULL);
    dbg_err_if (uri == NULL);
    /* is_valid_uri may be NULL */
    /* arg may be NULL */

    request_clear_uri(rq);

    /* this is just to avoid recursive infinite redirect loops for pages that
       appends something to the URI and redirects to the same page */
    warn_err_ifm(strlen(uri) >= 4096, "Request URI too long");

    REQUEST_SET_STRING_FIELD(rq->uri, uri);

    /* save (undecoded) query string i.e. everything after '?' */
    if((p = strchr(uri, '?')) != NULL)
        dbg_err_if(request_set_query_string(rq, ++p));

    return request_split_uri(rq, is_valid_uri, arg);
err:
    return ~0;
}

/* split the path again, e.g. once the virtual host is known: the request
 * line is read before the Host field (the other fields are kept) */
int request_resplit_uri(request_t *rq,
        int (*is_valid_uri)(void*, const char *, size_t), void* arg)
{
    return request_split_uri(rq, is_valid_uri, arg);
}

static int request_set_proto(request_t *rq, const char *proto)
{
    dbg_err_if (rq == NULL);
    dbg_err_if (proto == NULL);

    /* be sure that the requested protocol is http */
    if(strcmp(proto, "HTTP/1.0") && strcmp(proto, "HTTP/1.1"))
        return ~0; /* unknown or unsupported protocol */

    REQUEST_SET_STRING_FIELD(rq->protocol, proto);

    return 0;
err:
    return ~0;
}

/*
 * \ingroup request
 * \brief   Save client request
 *
 * Save client request line
 *
 * \param rq     request object
 * \param ln     the request line
 *
 * \return \c 0 if successful, non-zero on error
 */
int request_set_client_request(request_t *rq, const char *ln)
{
    char *p;
    dbg_err_if(rq == NULL);
    dbg_err_if(ln == NULL);

    rq->cli_rq = u_strdup(ln);
    dbg_err_if(rq->cli_rq == NULL);

    /* cut the trailing newline if any */
    for(p = rq->cli_rq; *p && (*p != '\r' && *p != '\n'); ++p)
        continue;
    *p = 0;

    return 0;
err:
    return ~0;
}

/**
 * \ingroup request
 * \brief   Return the client request line
 *
 * Return the client request (METHOD URI HTTP/HTTP_VERSION)
 *
 * \param rq     request object
 *
 * \return \c 0 if successful, non-zero on error
 */
const char *request_get_client_request(request_t *rq)
{
    return rq->cli_rq;
}

/*
 * Set the \p method of request \p rq.  Refer to http.h for possible methods.
 *
 * \param rq     request object
 * \param method the HTTP method 
 *
 * \return \c 0 if successful, non-zero on error
 */
int request_set_method(request_t *rq, const char *method)
{
    dbg_return_if (rq == NULL, ~0);
    dbg_return_if (method == NULL, ~0);

    if(!strcasecmp(method, "get"))
        rq->method = HM_GET;
    else if(!strcasecmp(method, "head"))
        rq->method = HM_HEAD;
    else if(!strcasecmp(method, "post"))
        rq->method = HM_POST;
    else if(!strcasecmp(method, "put"))
        rq->method = HM_PUT;
    else if(!strcasecmp(method, "delete"))
        rq->method = HM_DELETE;
    else if(!strcasecmp(method, "patch"))
        rq->method = HM_PATCH;
    else {
        /* put, delete, * */
        rq->method = HM_UNKNOWN;
        return ~0; /* unknown or unsupported method */
    }
    
    return 0;
}

static int request_set_content_length(request_t *rq)
{
    const char *clen;
    size_t len = 0;
    unsigned int digit;

    dbg_err_if (rq == NULL);

    clen = header_get_field_value(rq->header, "Content-Length");
    dbg_err_if(clen == NULL);
    while (*clen == ' ' || *clen == '\t')
        ++clen;
    dbg_err_if(*clen < '0' || *clen > '9');

    /* Accept decimal digits only and check before multiplying. atoi() can
     * overflow and its negative result was converted to unsigned size_t. */
    for (; *clen >= '0' && *clen <= '9'; ++clen)
    {
        digit = (unsigned int)(*clen - '0');
        dbg_err_if(len > ((size_t)-1 - digit) / 10);
        len = len * 10 + digit;
    }
    while (*clen == ' ' || *clen == '\t')
        ++clen;
    dbg_err_if(*clen != '\0');

    rq->content_length = len;

    return 0;
err:
    return ~0;
}

static int request_parse_cookie(request_t *rq, field_t *field)
{
    enum { BUFSZ = 4096 }; /* cookie size limit */
    char *pp, *tok, *src, buf[BUFSZ];

    dbg_err_if (rq == NULL);
    dbg_err_if (field == NULL);
    
    dbg_err_if(field_get_value(field) == NULL);

    /* save a copy to tokenize it */
    u_strlcpy(buf, field_get_value(field), sizeof buf);

    /* foreach name=value pair... */
    for(src = buf; (tok = strtok_r(src, " ;", &pp)) != NULL; src = NULL)
        dbg_if(vars_add_urlvar(request_vars(rq, &rq->cookies), tok, NULL));

    return 0;
err:
    return ~0;
}

static int request_parse_cookies(request_t *rq)
{
    field_t *f;

    dbg_err_if (rq == NULL);

    for(f = NULL; (f = header_next_field(rq->header, "cookie", f)) != NULL; )
        dbg_err_if(request_parse_cookie(rq, f));

    return 0;
err:
    return ~0;
}

static int request_cb_add_var(vars_t *args, vars_t *also_to, const char *tok)
{
    var_t *v = NULL;

    dbg_err_if(args == NULL);
    dbg_err_if(also_to == NULL);
    dbg_err_if(tok == NULL);

    /* may fail with bad var encoding (url?a=b&v); bad vars are ignored */
    dbg_if(vars_add_urlvar(args, tok, &v));

    if(v)
    {
        /* add the ptr also to the other vars list */
        dbg_err_if(vars_add(also_to, v));
    }

    return 0;
err:
    return ~0;
}


static int request_cb_add_post_var(void *arg, const char *tok)
{
    request_t *rq = (request_t*)arg;

    return request_cb_add_var(request_vars(rq, &rq->args),
            request_vars(rq, &rq->args_post), tok);
}

static int request_cb_add_get_var(void *arg, const char *tok)
{
    request_t *rq = (request_t*)arg;

    return request_cb_add_var(request_vars(rq, &rq->args),
            request_vars(rq, &rq->args_get), tok);
}

static int foreach_query_var(const char *urlquery, int offset, 
        int(*cb)(void*,const char*), void *arg)
{
    char *pp, *tok, *src, *query = NULL;

    dbg_err_if(offset < 0);
    dbg_err_if(cb == NULL);

    if(!urlquery)
        return 0; /* no args */

    /* dup to tokenize it */
    query = u_strdup(urlquery + offset);
    dbg_err_if(query == NULL);

    /* foreach name=value pair... */
    for(src = query; (tok = strtok_r(src, "&", &pp)) != NULL; src = NULL)
    {
        /* call the callback that will save this var */
        dbg_err_if(cb(arg, tok));
    }

    U_FREE(query);

    return 0;
err:
    U_FREE(query);
    return ~0;
}

static int request_parse_query_args(request_t *rq)
{
    dbg_err_if(rq == NULL);

    return foreach_query_var(rq->query, 0, request_cb_add_get_var, (void*)rq); 
err:
    return ~0;
}

/* set is-cgi flag */
void request_set_cgi(request_t *rq, int cgi)
{
    rq->cgi = cgi;
    return;
}

/** 
 * \ingroup request
 * \brief   Get the content length of a request
 *  
 * Retrieve a size_t corresponding to the \e Content-Length field of request 
 * \p rq
 *
 * \param rq    request object
 *  
 * \return the content length of the given \p rq
 */
ssize_t request_get_content_length(request_t *rq)
{
    dbg_return_if (rq == NULL, -1);

    return (ssize_t) rq->content_length;
}

static int match_content_type(header_t *h, const char *mime_type)
{
    const char *ct;

    dbg_return_if (h == NULL, 0);
    dbg_return_if (mime_type == NULL, 0);

    ct = header_get_field_value(h, "Content-Type");
    if(ct == NULL || strncasecmp(ct, mime_type, strlen(mime_type)))
        return 0;

    return 1;
}

static int request_is_content_type(request_t *rq, const char *ct)
{
    return match_content_type(rq->header, ct);
}

static int request_is_multipart_formdata(request_t *rq)
{
    return request_is_content_type(rq, "multipart/form-data");
}

static int request_is_urlencoded(request_t *rq)
{
    if(header_get_field_value(rq->header, "Content-Type") == NULL)
        return 1; /* yes; no content-type field provided */

    if(request_is_content_type(rq, "application/x-www-form-urlencoded"))
        return 1; /* yes */

    return 0; /* no */
}

static int request_parse_urlencoded_data(request_t *rq)
{
    ssize_t qsz, len;

    dbg_err_if (rq == NULL);

    len = rq->content_length; /* shortcut */

    qsz = (rq->query ? strlen(rq->query) : 0);

    /* alloc or enlarge the query string buffer */
    rq->query = u_realloc(rq->query, len + qsz + 2);
    dbg_err_if(rq->query == NULL);

    /* u_dbg("rq->query %x  size %u", rq->query, len+qsz+2); */

    rq->query[qsz] = 0; /* must be zero-term for strcat to work */
    if(qsz)
    {   /* append a '&' */
        strcat(rq->query, "&");
        ++qsz;
    }

    /* append to current query string */
    dbg_err_if(io_read(rq->io, rq->query + qsz, len) != len);

    /* zero terminate it */
    rq->query[qsz + len] = 0;

    /* parse and add post vars to the rq->args and rq->args_post array */
    dbg_err_if(foreach_query_var(rq->query, qsz, 
                request_cb_add_post_var, (void*)rq));

    return 0;
err:
    return ~0;
}

/* return the value of the param named 'param_name' of the field 'field_name'
   and save it to 'buffer' */
static int request_get_fieldparam(request_t *rq, const char *field_name, 
    const char *param_name, char *buf, size_t size)
{
    const char *param_value, *field_value, *p;
    size_t pv_len;

    dbg_err_if (rq == NULL);
    dbg_err_if (field_name == NULL);
    dbg_err_if (param_name == NULL);
    dbg_err_if (buf == NULL);
    dbg_err_if (size == 0);

    field_value = header_get_field_value(rq->header, field_name);
    dbg_err_if(field_value == NULL);

    /* look for param name=value pair */
    param_value = u_stristr(field_value, param_name);
    dbg_err_if(param_value == NULL);

    /* skip param name */
    param_value += strlen(param_name);

    /* first char must be an equal sign */
    dbg_err_if(*param_value++ != '=');

    /* a param value ends on the first ';', space or at the end of string */
    for(p = param_value; ; ++p)
        if(*p == '\0' || *p == ';' || isspace((unsigned char) *p))
            break; /* end of param value */

    /* param value len */
    pv_len = p - param_value;

    /* boundary check */
    dbg_err_if(pv_len + 1 > size); 

    /* copy out the param value */
    (void) u_strlcpy(buf, param_value, pv_len + 1);

    return 0;
err:
    return ~0;
}

static int is_multipart_mixed(header_t *h)
{
    return match_content_type(h, "multipart/mixed");
}

static int is_encoded(header_t *h)
{
    const char *cte;

    dbg_return_if (h == NULL, 0);

    if((cte = header_get_field_value(h, "Content-Transfer-Encoding")) == NULL)
        return 0; /* not encoded */

    if(strcasecmp(cte, "binary") == 0)
        return 0; /* not encoded */

    return 1; /* encoded */
}

static inline int is_quote(char c)
{
    return (c == '"' || c == '\'' ? c : 0);
}

static int parse_content_disposition(header_t *h, char *name, char *filename,
    size_t prmsz)
{
    enum { BUFSZ = 512 };
    char *pp, *tok, *src, buf[BUFSZ];
    size_t n_len, fn_len;
    const char *cd;
    int q;

    dbg_err_if (h == NULL);
    dbg_err_if (name == NULL);
    dbg_err_if (filename == NULL);
    dbg_err_if (prmsz == 0);
    
    cd = header_get_field_value(h, "Content-Disposition");
    dbg_err_if(cd == NULL);

    dbg_err_if(strlen(cd) >= BUFSZ);

    /* must start with form-data */
    dbg_err_if(strncmp(cd, "form-data", strlen("form-data")));

    name[0] = filename[0] = '\0';

    /* save a copy to tokenize it */
    u_strlcpy(buf, cd, sizeof buf);

    /* shortcut */
    n_len = strlen("name=");
    fn_len = strlen("filename=");

    /* foreach name=value pair... */
    for(src = buf; (tok = strtok_r(src, ";", &pp)) != NULL; src = NULL)
    {
        /* skip trailing blanks */
        while(isspace((unsigned char) *tok))
            ++tok;

        if(strncmp(tok, "form-data", strlen("form-data")) == 0)
        {
            continue;   /* skip */
        }
        else if(strncmp(tok, "name=", n_len) == 0) 
        {
            /* skip the name part */
            tok += n_len;

            /* remove single or double quotes */
            if((q = is_quote(tok[0])) != 0)
                ++tok;
            if(strlen(tok) && tok[strlen(tok) - 1] == q)
                tok[strlen(tok) - 1] = '\0';

            dbg_if (u_strlcpy(name, tok, prmsz));
        } 
        else if(strncmp(tok, "filename=", fn_len) == 0) 
        {
            /* skip the filename part */
            tok += fn_len;

            /* remove single or double quotes */
            if((q = is_quote(tok[0])) != 0)
                ++tok;
            if(strlen(tok) && tok[strlen(tok) - 1] == q)
                tok[strlen(tok) - 1] = '\0';

            dbg_if (u_strlcpy(filename, tok, prmsz));
        } 
        /* else ignore unknown fields */
    }
            
    return 0;
err:
    return ~0;
}

/* 
 * Read from io until obuf is full or until stop_at string is found.
 *
 * Returns the number of bytes written to obuf 
 */
static ssize_t read_until(io_t *io, const char *stop_at, char *obuf, 
    size_t size, int *found)
{
    char *dst = obuf;
    const char *ptr = stop_at, *end = stop_at + strlen(stop_at);
    int rc;
    size_t slen = strlen(stop_at);

    dbg_err_if(size < slen); /* stop_at can't be bigger then the output buf */

    for(*found = 0; *found == 0; )
    {
        /* at all times the output buffer must be big enough to contain the 
         * boundary string so everytime we meet the first char of the boundary 
         * we check the avail size of the output buffer and return if the 
         * whole boundary doesn't fit into it (read_until will be called 
         * again with an empty output buffer) */
        if(ptr == stop_at && size < slen + 1)
            break;

        rc = io_read(io, dst, 1);
        dbg_err_if(rc < 0);

        if(rc == 0)
            break; /* eof */

        if(*ptr != *dst)
            ptr = stop_at;

        if(*ptr == *dst && ++ptr == end)
            *found = 1;

        dst++;
        size--;
    }

    return dst - obuf;
err:
    return -1;
}


/**
 * \ingroup request
 * \brief   Get uploaded files
 *
 * Return the list of uploaded files. 
 *
 * Any var_t in the list will contain, 
 * within its name/value pair, the name of the HTML form input tag "name" 
 * argument and the filename (with full path) of the temporary file where
 * uploaded content has been stored.
 *
 * This function is only useful to enumerate uploads, 
 * \sa request_get_uploaded_file is what you'll probably use.
 *
 * \param rq  request object
 *
 * \return the arguments' list of the given \p rq
 */
vars_t *request_get_uploads(request_t *rq)
{
    return request_vars(rq, &rq->uploads);
}

/*
 * name:         form "name" <input> tag attribute value
 * filename:     name of the uploaded file provided by the client
 * tmp_filename: name on the temp file when the uploaded data has been saved
 *               on the local disk
 * mime_type:    uploaded MIME type as stated by the browser (may be NULL)
 */
static int request_add_uploaded_file(request_t *rq, const char *name, 
    const char *filename, const char *tmp_filename, const char *mime_type)
{
    struct stat st;
    var_t *v = NULL;
    upload_info_t *info = NULL;

    dbg_err_if (rq == NULL);
    dbg_err_if (name == NULL);
    /* filename may be NULL */
    dbg_err_if (tmp_filename == NULL);
    /* mime_type may be NULL */

    dbg_err_sif (stat(tmp_filename, &st) < 0);

    /* create a new var obj */
    dbg_err_if(var_create(name, tmp_filename, &v));

    /* alloc an info struct to attach to the var_t obj */
    dbg_err_if((info = u_zalloc(sizeof(upload_info_t))) == NULL);

    /* set info data */
    info->size = st.st_size;
    if(mime_type)
        snprintf(info->mime_type, MIME_TYPE_BUFSZ, "%s", mime_type);
    else
        info->mime_type[0] = 0;

    if(filename)
        snprintf(info->filename, U_FILENAME_MAX, "%s", filename);

    /* attach info to v */
    var_set_opaque(v, info);
    info = NULL;

    /* push into the cookie list */
    dbg_err_if(vars_add(request_vars(rq, &rq->uploads), v));

    return 0;
err:
    if(info)
        U_FREE(info);
    if(v)
        var_free(v);
    return ~0;
}

static int request_get_uploaded_filev(request_t *rq, var_t *v,
    char local_filename[U_FILENAME_MAX], char client_filename[U_FILENAME_MAX],
    char mime_type[MIME_TYPE_BUFSZ], size_t *file_size)
{           
    upload_info_t *info;
    const char *tmp_fqn;

    dbg_err_if (rq == NULL);
    dbg_err_if (v == NULL);
    dbg_err_if (local_filename == NULL);
    dbg_err_if (client_filename == NULL);
    dbg_err_if (mime_type == NULL);
    dbg_err_if (file_size == NULL);

    info = var_get_opaque(v);
    dbg_err_if(info == NULL);

    tmp_fqn = var_get_value(v);
    dbg_err_if(tmp_fqn == NULL);

    /* copy out return values */
    u_strlcpy(local_filename, tmp_fqn, U_FILENAME_MAX);
    u_strlcpy(mime_type, info->mime_type, MIME_TYPE_BUFSZ);
    u_strlcpy(client_filename, info->filename, U_FILENAME_MAX);
    *file_size = info->size;

    return 0;
err:
    return ~0;
}

/** 
 * \ingroup request
 * \brief   Get info and handles of an uploaded file
 *  
 * Return information and handles about an uploaded file 
 *
 * \param rq    request object
 * \param name  form input tag variable name (&lt;input type=file name="xxx"&gt;)
 * \param idx   if more then one file with the same name param exists idx will 
 *              be used as an index (use 0 otherwise)
 * \param local_filename    on successfull exit will get the filename (with 
 *                          full path) of the temporary file where uploaded 
 *                          file content has been saved. 
 *                          Must be at least U_FILENAME_MAX bytes long
 * \param client_filename   filename as provided by the client
 *                          Must be at least U_FILENAME_MAX bytes long
 * \param mime_type         MIME type as stated y the client (may be "")
 *                          Must be at least MIME_TYPE_BUFSZ bytes long
 * \param file_size         file size of the uploaded file
 *  
 * \return \c 0 on success, \c ~0 otherwise
 */
int request_get_uploaded_file(request_t *rq, const char *name, size_t idx,
    char local_filename[U_FILENAME_MAX], char client_filename[U_FILENAME_MAX],
    char mime_type[MIME_TYPE_BUFSZ], size_t *file_size)
{
    var_t *v;

    dbg_err_if (rq == NULL);
    dbg_err_if (name == NULL);
    dbg_err_if (idx >= vars_count(request_vars(rq, &rq->uploads)));
    dbg_err_if (local_filename == NULL);
    dbg_err_if (client_filename == NULL);
    dbg_err_if (mime_type == NULL);
    dbg_err_if (file_size == NULL);

    v = vars_geti(request_vars(rq, &rq->uploads), name, idx);
    dbg_err_if(v == NULL);

    return request_get_uploaded_filev(rq, v, local_filename, client_filename,
        mime_type, file_size);
err:
    return ~0;
}

static ssize_t request_read_until_boundary(request_t *rq, io_t *io, 
        const char *boundary, char *buf, size_t size, u_buf_t **pubuf)
{
    u_buf_t *ubuf = NULL;
    int found;
    size_t bound_len, trb;
    ssize_t rc;

    /* shortcut */
    bound_len = strlen(boundary);

    trb = 0;

    for(found = 0; !found; /* nothing */)
    {
        rc = read_until(io, boundary, buf, size, &found);
        dbg_err_if(rc <= 0); /* on error or eof exit */

        /* write all but the last bound_len + 2 (\r\n) bytes */
        if(found)
        {
            rc -= bound_len;
            dbg_err_if(rc < 0);

            /* zero-term the buffer (removing the boundary) */
            buf[rc] = 0;

        } else {

            /* buffer too small, alloc (and use) a dynamic buffer */
            if(ubuf == NULL)
            {
                dbg_err_if(u_buf_create(&ubuf));
                dbg_err_if(u_buf_reserve(ubuf, 2 * size));
            }
        }

        /* total read bytes */
        trb += rc;

        warn_err_ifm(trb > rq->post_maxsize, "POST data exceed post_maxsize");

        /* if we're using the buf on the heap then append read data; rc will
         * be zero if the last read returned just the boundary (that it's  not
         * going to be written to the output buffer) */
        if(ubuf && rc)
            dbg_err_if(u_buf_append(ubuf, buf, rc));
    }

    *pubuf = ubuf;

    return (ubuf ? u_buf_len(ubuf) : rc);
err:
    if(ubuf)
        u_buf_free(ubuf);
    return -1;

}

enum { MULTIPART_BUFSZ = 4096 };

/* a file part: copy its data, up to the boundary, to a temporary file and
 * add it to the request's uploads ('h' is the part's header) */
static int request_save_upload(request_t *rq, io_t *io, const char *boundary,
    const char *name, const char *filename, header_t *h)
{
    io_t *tmpio = NULL;
    char buf[MULTIPART_BUFSZ];
    size_t bound_len = strlen(boundary);
    int found;
    ssize_t rc;

    dbg_err_if(sizeof(buf) <= bound_len);

    /* open a temporary file to dump uploaded data */
    dbg_err_if(u_tmpfile_open(rq->temp_dir, &tmpio));

    for(found = 0; !found; /* nothing */)
    {
        rc = read_until(io, boundary, buf, sizeof(buf), &found);
        dbg_err_if(rc <= 0); /* on error or eof exit */

        /* write all but the last bound_len bytes (i.e. the boundary) */
        if(found)
        {
            rc -= bound_len;
            dbg_err_if(rc < 0);
        }

        /* write to the temp file */
        dbg_err_if(io_write(tmpio, buf, rc) < 0);
    }

    /* save the path/name of the tmp file to buf */
    dbg_err_if(io_name_get(tmpio, buf, sizeof(buf)));

    /* flush and free */
    io_free(tmpio); tmpio = NULL;

    /* add this file to the uploaded file list */
    dbg_err_if(request_add_uploaded_file(rq, name, filename, buf,
        header_get_field_value(h, "Content-Type")));

    return 0;
err:
    if(tmpio) {
        /* free space occupied by partial uploads */
        if(io_name_get(tmpio, buf, sizeof(buf)) == 0)
            u_remove(buf);
        io_free(tmpio);
    }
    return ~0;
}

/* a form field part: its data, up to the boundary, becomes a (binary)
 * request argument, also listed in the POST arguments */
static int request_save_field(request_t *rq, io_t *io, const char *boundary,
    const char *name)
{
    char buf[MULTIPART_BUFSZ];
    u_buf_t *ubuf = NULL;
    var_t *v = NULL;
    vars_t *args;
    ssize_t rc;

    /* read data before the boundary into the buffer. if the buffer is too
       small the function will return all data in a new ubuf that must be
       freed by the caller */
    rc = request_read_until_boundary(rq, io, boundary, buf, sizeof(buf), &ubuf);
    dbg_err_if(rc < 0);

    dbg_err_if(var_bin_create(name,
                (ubuf ? u_buf_ptr(ubuf) : buf),
                (ubuf ? u_buf_len(ubuf) : rc),
                &v));

    /* rq->args owns v (args_post only links to it, see request_vars) */
    dbg_err_if((args = request_vars(rq, &rq->args)) == NULL);
    dbg_err_if(vars_add(args, v));
    dbg_if(vars_add(request_vars(rq, &rq->args_post), v));
    v = NULL;

    if(ubuf)
        u_buf_free(ubuf);

    return 0;
err:
    if(v)
        var_free(v);
    if(ubuf)
        u_buf_free(ubuf);
    return ~0;
}

/* after the closing boundary: read and ignore the epilogue (if any) */
static void request_skip_epilogue(request_t *rq, io_t *io)
{
    char buf[MULTIPART_BUFSZ];
    size_t rall = rq->content_length + rq->body_off;

    while(io->rtot < rall)
    {
        if(io_read(io, buf, U_MIN(rall - io->rtot, sizeof(buf))) <= 0)
            break;
    }
}

static int request_parse_multipart_chunk(request_t *rq, io_t *io,
    const char *boundary, int *eof)
{
    enum { PRMSZ = 512 };
    header_t *h = NULL;
    char name[PRMSZ], filename[PRMSZ], buf[2];

    /* create an header object to parse MIME part headers */
    dbg_err_if(header_create(&h));

    /* read header lines until the first blank line */
    dbg_err_if(header_load(h, io));

    warn_err_ifm(is_multipart_mixed(h),
        "multipart/mixed content is not supported yet");

    /* HTTP should never use cte */
    warn_err_ifm(is_encoded(h),
        "encoded file upload is not supported");

    dbg_err_if(parse_content_disposition(h, name, filename, PRMSZ));

    if(filename[0] != '\0')
        dbg_err_if(request_save_upload(rq, io, boundary, name, filename, h));
    else
        dbg_err_if(request_save_field(rq, io, boundary, name));

    /* will read "\r\n" for not-ending boundaries, "--" otherwise */
    dbg_err_if(io_read(io, buf, 2) <= 0);

    if(strncmp(buf, "--", 2) == 0)
    {
        *eof = 1; /* end of MIME stuff */
        request_skip_epilogue(rq, io);
    }

    header_free(h);

    return 0;
err:
    if(h)
        header_free(h);
    return ~0;
}

static int request_parse_multipart_data(request_t *rq)
{
    enum { BOUNDARY_BUFSZ = 128, BUFSZ = 1024 }; 
    char boundary[BOUNDARY_BUFSZ], nl_boundary[BOUNDARY_BUFSZ], buf[BUFSZ];
    int eof, rc;

    /* boundary lines must start with -- */
    strcpy(boundary, "--");

    dbg_err_if(request_get_fieldparam(rq, "Content-Type", "boundary",
        boundary + 2, BOUNDARY_BUFSZ - 2));

    dbg_err_if(strlen(boundary) == 0);

    /* skip the MIME preamble (usually not used in HTTP) */
    for(;;)
    {
        dbg_err_if((rc = io_gets(rq->io, buf, BUFSZ)) <= 0);
        if(!strncmp(buf, boundary, strlen(boundary)))
            break; /* boundary found */
    }

    /* nl_boundary will contain: "\r\n--" + boundary */
    strcpy(nl_boundary, "\r\n");
    dbg_err_if(u_strlcat(nl_boundary, boundary, sizeof(nl_boundary)));

    /* cycle on each MIME part */
    for(eof = 0; eof == 0; )
        dbg_err_if(request_parse_multipart_chunk(rq, rq->io, nl_boundary,&eof));

    return 0;
err:
    return ~0;
}

/* alarm callback (it runs in ordinary code, see timer.h): a read or write
 * waiting on the connection then fails */
static int request_cb_close_socket(talarm_t *al, void *arg)
{
    io_t *io = (io_t*)arg;

    u_unused_args(al);

    warn("[%p] connection timed out, closed", (void *) io);

    /* close the stream (but not free it) */
    io_close(io);

    return 0;
}

/* an idle kept-alive connection timed out: close it silently */
static int request_cb_close_idle(talarm_t *al, void *arg)
{
    u_unused_args(al);

    io_close((io_t*)arg);

    return 0;
}

static int request_parse_data_once(request_t *rq);

/* parse the arguments and the form body, once (the validators of
   validate.c run it before the page, which runs it again) */
int request_parse_data(request_t *rq)
{
    if(rq->data_parsed)
        return rq->data_rc;

    rq->data_rc = request_parse_data_once(rq);
    rq->data_parsed = 1;

    return rq->data_rc;
}

static int request_parse_data_once(request_t *rq)
{
    talarm_t *al = NULL;
    io_t *io = request_io(rq);
    int rc = HTTP_STATUS_BAD_REQUEST;

    if(rq->method == HM_POST)
    {
        /* some vars may be urlencoded */
        dbg_err_if(request_parse_query_args(rq));

        /* Content-Length is required when using POST */
        dbg_err_if(request_set_content_length(rq) && 
            (rc = HTTP_STATUS_LENGTH_REQUIRED));

        if(rq->content_length == 0)
            return 0; /* no data posted */

        /* bytes read so far; will be used to know how many bytes we can read
         * from the client based on "Content-Length" value */
        rq->body_off = io->rtot;

        /* set a timeout to abort POST if it takes too long ... */
        dbg_err_if(timerm_add(rq->post_timeout, request_cb_close_socket, 
            (void*)rq->io, &al));

        /* abort if the client is pushing too much data */
        dbg_err_if(rq->content_length > rq->post_maxsize &&
            (rc = HTTP_STATUS_REQUEST_TOO_LARGE));

        if(request_is_multipart_formdata(rq))
        { 
            /* <form enctype="multipart/form-data" ...> */
            dbg_err_if(request_parse_multipart_data(rq));
        } else if(request_is_urlencoded(rq)) {
            /* if there's no content-type field or
               <form [enctype="application/x-www-form-urlencoded"] ...> */
            dbg_err_if(request_parse_urlencoded_data(rq));
        } else {
            /* nothing to do, the user will handle incoming data in his .kl1 */
        }

        /* post timeout not expired, clear it */
        dbg_if(timerm_del(al)); al = NULL;
    } else {
        /* parse urlencoded variables and set var_t* array */
        dbg_err_if(request_parse_query_args(rq));
    }

    return 0;
err:
    if(al)
        dbg_if(timerm_del(al));
    return rc;
}

/* cache data found in broker_is_valid_uri so we don't have to look for it
   again in broker_serve */
void request_set_sup_info(request_t *rq, supplier_t *sup, void *handle, 
        time_t mtime)
{
    rq->si_sup = sup;
    rq->si_handle = handle;
    rq->si_mtime = mtime;

    return;
}

void request_get_sup_info(request_t *rq, supplier_t **psup, void **phandle, 
        time_t *pmtime)
{
    if(psup)
        *psup = rq->si_sup;

    if(phandle)
        *phandle = rq->si_handle;

    if(pmtime)
        *pmtime = rq->si_mtime;

    return;
}

/*
 * Parse request object \p rq.
 *
 * \param rq            request object
 * \param is_valid_uri  URI validation function
 * \param arg           argument to is_valid_uri
 *
 * \return \c 0 if successful, non-zero on error
 */
int request_parse_header(request_t *rq, 
        int (*is_valid_uri)(void*, const char *, size_t),
        void* arg)
{
    const char WP[] = " \t\r\n";
    char ln[REQUEST_LINE_MAX + 2], *pp, *method, *uri, *proto;
    talarm_t *al = NULL;
    size_t lengths = 0, codings = 0, start;
    field_t *field;
    int status;

    dbg_err_if (rq == NULL);
    dbg_err_if (rq->io == NULL); /* must call rq_bind before rq_parse */

    /* wait at most N seconds to receive the request */
    dbg_err_if(timerm_add(rq->idle_timeout, rq->ka_wait ?
        request_cb_close_idle : request_cb_close_socket, (void*)rq->io, &al));

    /* the previous request on this connection limited reads to its body */
    io_set_read_limit(rq->io, -1);

    start = rq->io->rtot;
    rq->parse_status = 0;

    if(!rq->cgi)
    {
        /* cp the first line */
        if(io_gets(rq->io, ln, sizeof ln) <= 0)
        {
            /* closed (or timed out) before sending anything */
            rq->conn_closed = (rq->io->rtot == start);
            goto err;
        }
        if(strchr(ln, '\n') == NULL)
        {
            /* too long, or the client stopped in the middle of it */
            if(strlen(ln) > REQUEST_LINE_MAX)
                rq->parse_status = HTTP_STATUS_URI_TOO_LONG;
            goto err;
        }

        /* save the verbatim request line */
        dbg_err_if(request_set_client_request(rq, ln));

        method = strtok_r(ln, WP, &pp); 
        dbg_err_if(!method || request_set_method(rq, method));

        uri = strtok_r(NULL, WP, &pp);
        dbg_err_if(!uri || request_set_uri(rq, uri, is_valid_uri, arg));

        /* HTTP/0.9 not supported yet */ 
        proto = strtok_r(NULL, WP, &pp);
        dbg_err_if(!proto || request_set_proto(rq, proto)); 
        dbg_err_if(strtok_r(NULL, WP, &pp) != NULL);

        if(header_load_request(rq->header, rq->io, rq->max_fields,
                    rq->max_line, rq->max_header, &status))
        {
            rq->parse_status = status;
            goto err;
        }
    } else {
        dbg_err_if(header_load_from_cgienv(rq->header));
    }

    /* request smuggling: a body framed two ways, or framed in a way one
     * server in the chain may read differently. Chunked transfer coding is
     * not implemented (501); with Content-Length too, or with a duplicate
     * Content-Length (even equal values), the request is refused (400) */
    rq->parse_status = HTTP_STATUS_BAD_REQUEST;
    for (field = NULL; (field = header_next_field(rq->header, NULL, field)); )
    {
        if (!strcasecmp(field_get_name(field), "Content-Length"))
            ++lengths;
        else if (!strcasecmp(field_get_name(field), "Transfer-Encoding"))
            ++codings;
    }
    nop_err_if(lengths > 1 || (codings && lengths));
    if (codings)
    {
        rq->parse_status = HTTP_STATUS_NOT_IMPLEMENTED;
        goto err;
    }
    if (lengths)
        nop_err_if(request_set_content_length(rq));

    /* the body limit (post_maxsize) holds for every method */
    if (rq->content_length > rq->post_maxsize)
    {
        rq->parse_status = HTTP_STATUS_REQUEST_TOO_LARGE;
        goto err;
    }

    /* set if-modified-since time_t value */
    dbg_err_if(request_parse_ims(rq));

    /* parse "Cookie:" fields and set the cookies vars_t */
    dbg_err_if(request_parse_cookies(rq));

    /* Content-Length is required when using POST */
    if(request_get_method(rq) == HM_POST)
        dbg_err_if(request_set_content_length(rq));

    /* idle timeout not expired, clear it */
    dbg_if(timerm_del(al)); al = NULL;

    /* the body (if any) starts here; reading it (parsers, pages, CGIs) can
       never go past its end, into the next request on the connection */
    rq->hdr_end = rq->io->rtot;
    io_set_read_limit(rq->io, (ssize_t) (rq->hdr_end + rq->content_length));

    return 0;
err:
    if(al)
        timerm_del(al);
    return ~0;
}

/**
 * \ingroup request
 * \brief   Wait for a request on a kept-alive connection
 *
 * Set the idle timeout for a request that follows another one on the same
 * connection; when it expires the connection is closed without a warning.
 *
 * \param rq       request object (not parsed yet)
 * \param timeout  seconds to wait for the request
 *
 * \return nothing
 */
void request_set_keep_alive_wait(request_t *rq, size_t timeout)
{
    rq->idle_timeout = U_MAX(1, timeout);
    rq->ka_wait = 1;
}

/**
 * \ingroup request
 * \brief   Tell if the client went away before sending a request
 *
 * \param rq  request object
 *
 * \return !0 if request_parse_header() failed because the connection was
 *         closed (or timed out) before the first byte of the request
 */
int request_conn_closed(request_t *rq)
{
    return rq->conn_closed;
}

/**
 * \ingroup request
 * \brief   Why request_parse_header() failed
 *
 * \param rq  request object
 *
 * \return the status to answer with (400, 413 body too large, 414 request
 *         line too long, 431 header too large, 501 transfer coding), or 0
 *         if there is nothing to answer (or it is a plain 400)
 */
int request_parse_status(request_t *rq)
{
    return rq->parse_status;
}

/**
 * \ingroup request
 * \brief   Tell if the client asked for a persistent connection
 *
 * HTTP/1.1 connections are persistent unless the client sends
 * "Connection: close"; HTTP/1.0 ones only with "Connection: keep-alive".
 *
 * \param rq  request object (parsed)
 *
 * \return !0 if the connection may be kept open after the response
 */
int request_keep_alive(request_t *rq)
{
    dbg_return_if (rq == NULL, 0);

    if(rq->cgi || rq->protocol == NULL)
        return 0;

    /* "close" wins over anything else */
    if(header_has_token(rq->header, "Connection", "close"))
        return 0;

    if(!strcmp(rq->protocol, "HTTP/1.1"))
        return 1;

    return header_has_token(rq->header, "Connection", "keep-alive");
}

/**
 * \ingroup request
 * \brief   Skip the unread part of the request body
 *
 * Read and discard what is left of the request body (up to \p max bytes),
 * so the next request on the same connection can be parsed.
 *
 * \param rq   request object
 * \param max  max number of bytes to discard
 *
 * \return \c 0 if the whole body has been consumed, non-zero if the
 *         connection cannot be reused
 */
int request_drain_body(request_t *rq, size_t max)
{
    enum { BUFSZ = 4096 };
    char buf[BUFSZ];
    talarm_t *al = NULL;
    size_t done, left;
    ssize_t c;

    dbg_err_if (rq == NULL);
    dbg_err_if (rq->io == NULL);

    done = rq->io->rtot - rq->hdr_end;

    /* more than the body has been read: the next request is gone */
    nop_err_if(done > rq->content_length);

    if((left = rq->content_length - done) == 0)
        return 0;

    /* the client may be waiting for "100 Continue" before sending it */
    nop_err_if(done == 0 && header_get_field(rq->header, "Expect"));

    nop_err_if(left > max);

    dbg_err_if(timerm_add(rq->idle_timeout, request_cb_close_idle,
        (void*)rq->io, &al));

    /* reads stop at the end of the body (see request_parse_header) */
    for(; left; left -= c)
        nop_err_if((c = io_read(rq->io, buf, U_MIN(left, BUFSZ))) <= 0);

    dbg_if(timerm_del(al)); al = NULL;

    return 0;
err:
    if(al)
        timerm_del(al);
    return ~0;
}

/** 
 * \ingroup request
 * \brief   Get the method of a request
 *  
 * Return the method of request \p rq. Refer to http.h for possible methods.
 *
 * \param rq    request object
 *  
 * \return
 *  - the method of the given \p rq  
 */
int request_get_method(request_t *rq)
{
    dbg_return_if (rq == NULL, HM_UNKNOWN);

    return rq->method;
}

/**
 * \ingroup request
 * \brief   Get the method of a request as a string
 *
 * \param rq  request object
 *
 * \return "GET", "HEAD", "POST", "PUT", "DELETE" or "UNKNOWN"
 */
const char *request_get_method_name(request_t *rq)
{
    switch(rq ? rq->method : HM_UNKNOWN)
    {
    case HM_GET:    return "GET";
    case HM_HEAD:   return "HEAD";
    case HM_POST:   return "POST";
    case HM_PUT:    return "PUT";
    case HM_DELETE: return "DELETE";
    case HM_PATCH:  return "PATCH";
    default:        return "UNKNOWN";
    }
}

/**
 * \ingroup request
 * \brief   Get the user who authenticated the request
 *
 * \param rq  request object
 *
 * \return the user name, or \c NULL if the page is not in an
 *         authentication realm (see doc/AUTH)
 */
const char *request_get_auth_user(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->auth_user;
}

/* a route (route.c) serves the request with 'page': it replaces the
   filename and the path info (the route matched the whole path) */
int request_set_route(request_t *rq, const char *page)
{
    dbg_err_if (rq == NULL || page == NULL);

    dbg_err_if(request_set_filename(rq, page));
    U_FREE(rq->path_info);
    U_FREE(rq->resolved_path_info);
    U_FREE(rq->resolved_filename);
    request_set_sup_info(rq, NULL, NULL, 0);

    return 0;
err:
    return ~0;
}

/* remove (and free) an argument: from the list that owns it and the GET
   or POST list that links to it */
int request_del_arg(request_t *rq, var_t *v)
{
    dbg_return_if (rq == NULL || v == NULL || rq->args == NULL, ~0);

    if(rq->args_get)
        (void) vars_del(rq->args_get, v);
    if(rq->args_post)
        (void) vars_del(rq->args_post, v);
    dbg_err_if(vars_del(rq->args, v));
    var_free(v);

    return 0;
err:
    return ~0;
}

/* the route parameters (NULL if none) */
vars_t *request_get_route_params(request_t *rq)
{
    return rq ? rq->route_params : NULL;
}

/* add a {name} value of the route (value: len bytes) */
int request_add_route_param(request_t *rq, const char *name,
        const char *value, size_t len)
{
    char *v = NULL;
    var_t *var = NULL;

    dbg_err_if (rq == NULL || name == NULL || value == NULL);

    dbg_err_if((v = u_malloc(len + 1)) == NULL);
    memcpy(v, value, len);
    v[len] = '\0';
    dbg_err_if(var_create(name, v, &var));
    dbg_err_if(request_vars(rq, &rq->route_params) == NULL);
    dbg_err_if(vars_add(rq->route_params, var));
    U_FREE(v);

    return 0;
err:
    U_FREE(v);
    if(var)
        var_free(var);
    return ~0;
}

/**
 * \ingroup request
 * \brief   Get a parameter of the route that matched the request
 *
 * For a route "/api/users/{id}" and the path "/api/users/42",
 * request_get_route_param(rq, "id") is "42" (see doc/ROUTES).
 *
 * \param rq    request object
 * \param name  parameter name
 *
 * \return the (URL-decoded) value, or \c NULL
 */
const char *request_get_route_param(request_t *rq, const char *name)
{
    dbg_return_if (rq == NULL || name == NULL, NULL);

    return rq->route_params ? vars_get_value(rq->route_params, name) : NULL;
}

static int request_cb_body_timeout(talarm_t *al, void *arg)
{
    u_unused_args(al);

    warn("request body not received in time, connection closed");
    io_close((io_t *) arg);

    return 0;
}

/**
 * \ingroup request
 * \brief   Read the request body
 *
 * Read the whole body (Content-Length bytes) of a request whose body the
 * server has not parsed, e.g. a JSON PUT, PATCH or POST, within
 * post_timeout.
 *
 * \param rq    request object
 * \param max   largest body accepted (also limited by post_maxsize)
 * \param pbuf  the body, NUL-terminated, to free with u_free()
 * \param plen  its length
 *
 * \return \c 0, ::HTTP_STATUS_REQUEST_TOO_LARGE if the body is too large,
 *         or \c ~0 on error (read failure, timeout, body already read)
 */
int request_read_body(request_t *rq, size_t max, char **pbuf, size_t *plen)
{
    talarm_t *al = NULL;
    char *buf = NULL;
    size_t len;

    dbg_return_if (rq == NULL || pbuf == NULL || plen == NULL, ~0);

    len = rq->content_length;
    nop_err_if(rq->io->rtot != rq->hdr_end);    /* read (in part) already */
    if(len > max || len > rq->post_maxsize)
        return HTTP_STATUS_REQUEST_TOO_LARGE;

    dbg_err_if((buf = u_malloc(len + 1)) == NULL);
    dbg_err_if(timerm_add(rq->post_timeout, request_cb_body_timeout, rq->io,
                &al));
    nop_err_if(len && io_read(rq->io, buf, len) != (ssize_t) len);
    timerm_del(al);
    buf[len] = '\0';

    *pbuf = buf;
    *plen = len;

    return 0;
err:
    if(al)
        timerm_del(al);
    U_FREE(buf);
    return ~0;
}

/**
 * \ingroup request
 * \brief   Parse a JSON request body
 *
 * \param rq   request object
 * \param max  largest body accepted
 * \param pj   the document, to free with json_free()
 *
 * \return \c 0, or the status to answer with: 415 if the Content-Type is
 *         not JSON, 413 if the body is too large, 400 if it is not valid
 *         JSON or cannot be read
 */
int request_get_json(request_t *rq, size_t max, json_t **pj)
{
    const char *ct;
    char *body = NULL;
    size_t len, n;
    int rc;

    dbg_return_if (rq == NULL || pj == NULL, HTTP_STATUS_BAD_REQUEST);

    /* application/json, or a +json type, with optional parameters */
    ct = request_get_field_value(rq, "Content-Type");
    n = ct ? strcspn(ct, "; \t") : 0;
    if(ct == NULL || !((n == 16 && !strncasecmp(ct, "application/json", 16)) ||
                (n > 5 && !strncasecmp(ct + n - 5, "+json", 5))))
        return HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE;

    if((rc = request_read_body(rq, max, &body, &len)) != 0)
        return rc == HTTP_STATUS_REQUEST_TOO_LARGE ? rc :
            HTTP_STATUS_BAD_REQUEST;

    rc = json_parse(body, len, pj, NULL, 0) ? HTTP_STATUS_BAD_REQUEST : 0;
    U_FREE(body);

    return rc;
}

/* set by auth_check(): 'user' and 'realm' stay owned by the configuration */
void request_set_auth(request_t *rq, const char *user, void *realm, int stale)
{
    rq->auth_user = user;
    rq->auth_realm = realm;
    rq->auth_stale = stale;
}

void *request_get_auth_realm(request_t *rq)
{
    return rq ? rq->auth_realm : NULL;
}

int request_get_auth_stale(request_t *rq)
{
    return rq ? rq->auth_stale : 0;
}

/** 
 * \ingroup request
 * \brief   Get the protocol used by the client request
 *  
 * Return the protocol of request \p rq ("HTTP/1.0", "HTTP/1.1", etc.)
 *
 * \param rq    request object
 *  
 * \return
 *  - the method of the given \p rq  
 */
const char* request_get_protocol(request_t *rq)
{
    dbg_return_if (rq == NULL, "unknown");

    return rq->protocol;
}

/** 
 * \ingroup request
 * \brief   Get resolved filename of a request
 *  
 * Return a string representing the resolved filename of request \p rq.
 *
 * \param rq    request object
 *  
 * \return the resolved file name bound to \p rq (may be \c NULL)
 */
const char *request_get_resolved_filename(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->resolved_filename;
}

/** 
 * \ingroup request
 * \brief   Get the resolved path info of a request.
 *  
 * Return a string representing the resolved path info of request \p rq.
 *
 * \param rq    request object
 *  
 * \return the resolved path info of the given \p rq (may be \c NULL)
 */
const char *request_get_resolved_path_info(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->resolved_path_info;
}

int request_print(request_t *rq)
{
    dbg_return_if (rq == NULL, ~0);

    u_dbg("method: %u", rq->method);
    u_dbg("uri: %s", rq->uri);
    u_dbg("proto: %s", rq->protocol);
    u_dbg("filename: %s", rq->filename);
    u_dbg("resolved filename: %s", rq->resolved_filename);
    u_dbg("path_info: %s", rq->path_info);
    u_dbg("resolved path_info: %s", rq->resolved_path_info);
    u_dbg("query: %s", rq->query);

    return 0;
}

static int request_load_config(request_t *rq)
{
    u_config_t *c;
    vhost_t *vhost;
    const char *v;

    dbg_err_if (rq == NULL);
    dbg_err_if (rq->http == NULL);

    dbg_err_if((vhost = http_get_vhost(rq->http, rq)) == NULL);

    /* read the vhost's settings once, not for every request */
    if(!vhost->rq_config_loaded)
    {
        /* vhost can override those fields */
        dbg_err_if((c = vhost->config) == NULL);

        /* defaults */
        vhost->rq_idle_timeout = REQUEST_DEFAULT_IDLE_TIMEOUT;
        vhost->rq_post_timeout = REQUEST_DEFAULT_POST_TIMEOUT;
        vhost->rq_post_maxsize = REQUEST_DEFAULT_POST_MAXSIZE;
        vhost->rq_max_fields = REQUEST_DEFAULT_MAX_FIELDS;
        vhost->rq_max_line = REQUEST_DEFAULT_MAX_LINE;
        vhost->rq_max_header = REQUEST_DEFAULT_MAX_HEADER;

        /* request header limits (431 beyond them) */
        if((v = u_config_get_subkey_value(c, "max_header_fields")) != NULL)
            vhost->rq_max_fields = U_MAX(8, atoi(v));
        if((v = u_config_get_subkey_value(c, "max_header_line")) != NULL)
            vhost->rq_max_line = U_MIN(65534, U_MAX(256, atoi(v)));
        if((v = u_config_get_subkey_value(c, "max_header_size")) != NULL)
            vhost->rq_max_header = U_MAX(1024, atoi(v));

        /* idle timeout */
        if((v = u_config_get_subkey_value(c, "idle_timeout")) != NULL)
            vhost->rq_idle_timeout = U_MAX(1, atoi(v));

        /* post timeout */
        if((v = u_config_get_subkey_value(c, "post_timeout")) != NULL)
            vhost->rq_post_timeout = U_MAX(5, atoi(v));

        /* post maxsize */
        if((v = u_config_get_subkey_value(c, "post_maxsize")) != NULL)
            vhost->rq_post_maxsize = U_MAX(1024, atoi(v));

        /* temp dir to use on file upload.  when 'NULL' use system default
           (a copy owned by the vhost) */
        if((v = u_config_get_subkey_value(c, "temp_dir")) != NULL)
            dbg_err_if((vhost->rq_temp_dir = u_strdup(v)) == NULL);

        vhost->rq_config_loaded = 1;
    }

    rq->idle_timeout = vhost->rq_idle_timeout;
    rq->post_timeout = vhost->rq_post_timeout;
    rq->post_maxsize = vhost->rq_post_maxsize;
    rq->max_fields = vhost->rq_max_fields;
    rq->max_line = vhost->rq_max_line;
    rq->max_header = vhost->rq_max_header;
    rq->temp_dir = vhost->rq_temp_dir;

    return 0;
err:
    return ~0;
}

int request_create(http_t *http, request_t **prq)
{
    request_t *rq = NULL;

    dbg_return_if (prq == NULL, ~0);
    dbg_return_if (http == NULL, ~0);

    /* zero all but the (512 bytes of) address strings */
    rq = u_malloc(sizeof(request_t));
    dbg_err_if(rq == NULL);
    memset(rq, 0, offsetof(request_t, local_addr));
    rq->local_addr[0] = rq->peer_addr[0] = '\0';

    dbg_err_if(header_create(&rq->header));

    /* the variable lists are created on first use (request_vars()) */

    rq->http = http;

    dbg_err_if(request_load_config(rq));

    *prq = rq;

    return 0;
err:
    if(rq)
        request_free(rq);
    return ~0;
}

static int request_unlink_uploads(var_t *v, void * arg)
{
    dbg_err_if (v == NULL);

    u_unused_args(arg);

    if(var_get_opaque(v) && var_get_value(v))
    {   /* it's a file var, unlink v->value */
        u_remove(var_get_value(v));
    }

err:
    return 0;
}

int request_free(request_t *rq)
{
    if (rq)
    {
        /* free internal stuff */
        request_clear_uri(rq);

        /* verbatim client request line */
        U_FREE(rq->cli_rq);

        if(rq->header)
            header_free(rq->header);

        if(rq->io)
            io_free(rq->io);

        if(rq->uploads)
        {
            /* unlink uploaded files (if any) */
            vars_foreach(rq->uploads, request_unlink_uploads, NULL);
            vars_free(rq->uploads);
        }

        if(rq->cookies)
            vars_free(rq->cookies);

        if(rq->args_get)
            vars_free(rq->args_get);

        if(rq->args_post)
            vars_free(rq->args_post);

        if(rq->args)
            vars_free(rq->args);

        if(rq->route_params)
            vars_free(rq->route_params);

        U_FREE(rq);
    }

    return 0;
}

/* save the local connected address in the request obj */
int request_set_addr(request_t *rq, const char *addr)
{
    dbg_return_if (rq == NULL, ~0);
    dbg_return_if (addr == NULL, ~0);

    return u_strlcpy(rq->local_addr, addr, sizeof rq->local_addr);
}

/* save the address of the connected peer in the request obj */
int request_set_peer_addr(request_t *rq, const char *addr)
{
    dbg_return_if (rq == NULL, ~0);
    dbg_return_if (addr == NULL, ~0);

    return u_strlcpy(rq->peer_addr, addr, sizeof rq->peer_addr);
}

/** 
 * \ingroup request
 * \brief   Return the local address
 *  
 * Return a string containing the address of the accepted the socket
 *
 * \param rq    request object
 *  
 * \return      the address string 
 */
const char *request_get_addr(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->local_addr;
}

/** 
 * \ingroup request
 * \brief   Return the peer address
 *  
 * Return a string containing the address of the connected peer
 *
 * \param rq    request object
 *  
 * \return      the address string
 */
const char *request_get_peer_addr(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->peer_addr;
}

/** 
 * \ingroup request
 * \brief   Return the header object
 *  
 * Return the header object
 *
 * \param rq    request object
 *  
 * \return      a pointer to an header_t type
 * \sa      header_t
 */
header_t* request_get_header(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->header;
}

/** 
 * \ingroup request
 * \brief   Get an header field
 *  
 * Return the header field named \p name.
 *
 * \param rq    request object
 * \param name  the name of the field
 *  
 * \return      the header field or NULL if the header is not found
 */
field_t* request_get_field(request_t *rq, const char *name)
{
    dbg_return_if (rq == NULL, NULL);
    dbg_return_if (name == NULL, NULL);

    return header_get_field(rq->header, name);
}

/** 
 * \ingroup request
 * \brief   Get the value of an header field
 *  
 * Return the value of an header field named \p name.
 *
 * \param rq    request object
 * \param name  the name of the field
 *  
 * \return      the value of the field or NULL if the field is not found
 */
const char* request_get_field_value(request_t *rq, const char *name)
{
    dbg_return_if (rq == NULL, NULL);
    dbg_return_if (name == NULL, NULL);

    return header_get_field_value(rq->header, name);
}

vhost_t* request_get_vhost(request_t *rq)
{
    dbg_return_if (rq == NULL, NULL);

    return rq->vhost; /* may be NULL */
}

int request_set_vhost(request_t *rq, vhost_t *vhost)
{
    dbg_return_if (rq == NULL, ~0);

    rq->vhost = vhost;

    return 0;
}

