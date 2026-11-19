/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <time.h>
#include <u/libu.h>
#include <klin/response.h>
#include <klin/utils.h>
#include <klin/io.h>
#include <klin/codec.h>
#include <klin/http.h>
#include <klin/rsfilter.h>

struct response_s
{
    http_t *http;           /* http server handle               */
    header_t *header;       /* output header                    */
    io_t *io;               /* output stream                    */
    int status;             /* http status code                 */
    int method;             /* HTTP request method              */
    int cgi;                /* if we're running in cgi context  */
    int http11;             /* client speaks HTTP/1.1           */
    int keep_alive;         /* keep the connection open         */
    int framed;             /* body framing has been decided    */
    int chunked;            /* body sent with chunked encoding  */
    int header_sent;        /* header has been printed          */
    int streaming;          /* sent as written (SSE, see sse.c) */
};

/**
 * \ingroup response
 * \brief   Set response content encoding field 
 * 
 * Set the \e Content-Encoding field in a response object \p rs to \p encoding.
 * 
 * \param rs        response object
 * \param encoding  encoding type 
 *
 * \return 
 *  - \c 0 if successful
 *  - \c ~0 if successful
 */
int response_set_content_encoding(response_t *rs, const char *encoding)
{
    dbg_err_if(encoding == NULL);

    dbg_err_if(header_set_field(rs->header, "Content-Encoding", encoding));

    return 0;
err:
    return ~0;
}

/**
 * \ingroup response
 * \brief   Add all header field that enable page caching (i.e. disable caching)
 * 
 * Adds all relevant Header fields to the current HTTP response to avoid 
 * browser caching. 
 *
 * The function will set/modify the following fields:
 *
 *    Cache-Control: no-cache, must-revalidate 
 *    Expires: Mon, 1 Jan 1990 05:00:00 GMT
 *    Pragma: no-cache
 * 
 * \param rs        response object
 *
 * \return 
 *  - \c 0 if successful
 *  - \c ~0 if successful
 */
int response_disable_caching(response_t *rs)
{
    dbg_err_if(response_set_field(rs, "Cache-Control", 
        "no-cache, must-revalidate"));

    dbg_err_if(response_set_field(rs, "Expires", 
        "Mon, 1 Jan 1990 05:00:00 GMT"));

    dbg_err_if(response_set_field(rs, "Pragma", "no-cache"));

    return 0;
err:
    return ~0;
}

/**
 * \ingroup response
 * \brief   Remove all headers that inhibit page caching
 * 
 * Remove all HTTP Header fields that (should) prevent browsers caching. This
 * should enable caching on specs-compliant browsers.
 *
 * Those fields are:
 *
 *    Cache-Control: 
 *    Expires: 
 *    Pragma: 
 * 
 * \param rs        response object
 *
 * \return 
 *  - \c 0 if successful
 *  - \c ~0 if successful
 */
int response_enable_caching(response_t *rs)
{
    dbg_err_if(response_del_field(rs, "Cache-Control"));

    dbg_err_if(response_del_field(rs, "Expires"));

    dbg_err_if(response_del_field(rs, "Pragma"));

    return 0;
err:
    return ~0;
}

/**
 * \ingroup response
 * \brief    Set the value of a cookie 
 *
 * Set the value of a cookie named \p name to \p value in response object \p rs.
 * Other fields that can be set are \p expire, \p path, \p domain, \p and secure.
 *  
 * \param rs        response object
 * \param name      cookie name
 * \param value     cookie value
 * \param expire    cookie expiration date
 * \param path      cookie path
 * \param domain    cookie domain
 * \param secure    cookie secure flag
 *
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_set_cookie(response_t *rs, const char *name, const char *value,
    time_t expire, const char *path, const char *domain, int secure)
{
    return response_set_cookie_ex(rs, name, value, expire, path, domain,
        secure ? RESPONSE_COOKIE_SECURE : 0);
}

int response_set_cookie_ex(response_t *rs, const char *name, const char *value,
    time_t expire, const char *path, const char *domain, int flags)
{
    enum { BUFSZ = COOKIE_MAX_SIZE, DATESZ = 64 };
    field_t *field = NULL;
    char buf[BUFSZ], date[DATESZ];
    const unsigned char *p;
    const char *same_site = NULL;
    int same_flags = flags & (RESPONSE_COOKIE_SAMESITE_LAX |
        RESPONSE_COOKIE_SAMESITE_STRICT | RESPONSE_COOKIE_SAMESITE_NONE);

    dbg_err_if(rs == NULL || name == NULL || *name == '\0');
    for (p = (const unsigned char *)name; *p; ++p)
        dbg_err_if(!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || strchr("!#$%&'*+-.^_`|~", *p)));
    dbg_err_if(same_flags && (same_flags & (same_flags - 1)));
    dbg_err_if(same_flags == RESPONSE_COOKIE_SAMESITE_NONE &&
        !(flags & RESPONSE_COOKIE_SECURE));
    if (same_flags == RESPONSE_COOKIE_SAMESITE_LAX) same_site = "Lax";
    if (same_flags == RESPONSE_COOKIE_SAMESITE_STRICT) same_site = "Strict";
    if (same_flags == RESPONSE_COOKIE_SAMESITE_NONE) same_site = "None";
    /* Attributes must not be able to inject cookies or additional headers. */
    if (path)
        for (p = (const unsigned char *)path; *p; ++p)
            dbg_err_if(*p < 32 || *p == 127 || *p == ';');
    if (domain)
        for (p = (const unsigned char *)domain; *p; ++p)
            dbg_err_if(*p < 32 || *p == 127 || *p == ';');

    dbg_err_if(u_snprintf(buf, sizeof(buf), "%s=", name));
    if (value)
        dbg_err_if(u_urlncpy_s(buf + strlen(buf), sizeof(buf) - strlen(buf),
            value, strlen(value), URLCPY_ENCODE) < 0);
    else
        expire = 1; /* a date in the past; retain scope/security attributes */
    if (expire)
    {
        dbg_err_if(u_tt_to_rfc822(date, expire));
        dbg_err_if(u_snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
            "; Expires=%s", date));
    }
    if (path)
        dbg_err_if(u_snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "; Path=%s", path));
    if (domain)
        dbg_err_if(u_snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "; Domain=%s", domain));
    if (flags & RESPONSE_COOKIE_SECURE)
        dbg_err_if(u_snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "; Secure"));
    if (flags & RESPONSE_COOKIE_HTTPONLY)
        dbg_err_if(u_snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "; HttpOnly"));
    if (same_site)
        dbg_err_if(u_snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "; SameSite=%s", same_site));
    dbg_err_if(field_create("Set-Cookie", buf, &field));
    dbg_err_if(header_add_field(rs->header, field));
    return 0;
err:
    if (field)
        field_free(field);
    return ~0;
}

/** 
 * \ingroup response
 * \brief   Set the response method
 *  
 * Set the response method of \p rs to \p method. For possible values of
 * method, refer to http.h.
 *
 * \param rs      response object
 * \param method  response method
 *  
 * \return
 *  - nothing
 */
void response_set_method(response_t *rs, int method)
{
    rs->method = method;
}

/** 
 * \ingroup response
 * \brief   Get the response method
 *  
 * Get the response method of \p rs. For possibile values of method, refer to
 * http.h.
 *
 * \param rs    response object
 *  
 * \return
 *  - the method of the given \p rs
 */
int response_get_method(response_t *rs)
{
    return rs->method;
}


/* set is-cgi flag */
void response_set_cgi(response_t *rs, int cgi)
{
    rs->cgi = cgi;
    return ;
}

/* calculate the approx max value of the current header (useful to alloc a
 * buffer big enough) */
size_t response_get_max_header_size(response_t *rs)
{
    field_t *field;
    size_t sz = 0;

    /* calc status line length */
    sz += 16; /* http/x.y nnn[n] \r\n */
    sz += strlen(http_get_status_desc(rs->status));

    for(field = NULL; (field = header_next_field(rs->header, NULL, field)); )
    {
        const char *p;

        sz += ((p = field_get_name(field)) != NULL) ? strlen(p) : 0;
        sz += ((p = field_get_value(field)) != NULL) ? strlen(p) : 0;
        sz += 4; /* blanks and new lines */
    }

    sz += 2; /* final \r\n */
    sz += 64; /* guard bytes */

    return sz;
}

/* 
 * \ingroup response
 * \brief   Output a response header 
 *
 * Print the header of \p rs to \p io.
 *
 * \param rs        response object
 * \param io        output I/O object
 * 
 * \return
 *  - \c 0 if successful
 *  - \c ~0 on error
 */
int response_print_header_to_io(response_t *rs, io_t *io)
{
    char *buf = NULL;
    size_t len;

    dbg_err_if(io == NULL);

    dbg_err_if(response_format_header(rs, 0, &buf, &len));
    dbg_err_if(io_write(io, buf, len) != (ssize_t) len);

    U_FREE(buf);

    return 0;
err:
    U_FREE(buf);
    return ~0;
}

/* write v in decimal and a '\0' to buf (at least 21 bytes); return the
 * number of digits. snprintf() is slow for this, and it is done for every
 * status line and Content-Length */
static size_t response_ultoa(char *buf, unsigned long v)
{
    char tmp[24], *p = tmp + sizeof(tmp);
    size_t n;

    do {
        *--p = (char) ('0' + v % 10);
        v /= 10;
    } while(v);

    n = (size_t) (tmp + sizeof(tmp) - p);
    memcpy(buf, p, n);
    buf[n] = '\0';

    return n;
}

/*
 * \ingroup response
 * \brief   Format a response header
 *
 * Format the header of \p rs (status line, fields and the empty line that
 * ends it) into a new buffer, leaving \p extra spare bytes after it (e.g.
 * for the start of the body). The header is final once formatted.
 *
 * \param rs        response object
 * \param extra     spare bytes allocated after the header
 * \param pbuf      the new buffer, to be freed with u_free()
 * \param plen      the length of the header in \p *pbuf
 *
 * \return
 *  - \c 0 if successful
 *  - \c ~0 on error
 */
int response_format_header(response_t *rs, size_t extra, char **pbuf,
        size_t *plen)
{
    size_t cap = 0;

    dbg_return_if (pbuf == NULL, ~0);

    *pbuf = NULL;

    return response_format_header_reuse(rs, extra, pbuf, &cap, plen);
}

/*
 * \ingroup response
 * \brief   Format a response header into a reused buffer
 *
 * Like response_format_header(), but \p *pbuf (\p *pcap bytes, or NULL and
 * 0) is used if large enough, and replaced by a larger one otherwise; the
 * caller frees it when done with all the headers formatted in it.
 *
 * \param rs        response object
 * \param extra     spare bytes needed after the header
 * \param pbuf      the buffer, to be freed with u_free()
 * \param pcap      its size
 * \param plen      the length of the header in \p *pbuf
 *
 * \return
 *  - \c 0 if successful
 *  - \c ~0 on error (\p *pbuf and \p *pcap are left as they were)
 */
int response_format_header_reuse(response_t *rs, size_t extra, char **pbuf,
        size_t *pcap, size_t *plen)
{
    enum { STATUSSZ = 128 };
    char status[STATUSSZ], *buf = NULL, *p;
    const char *desc;
    size_t sz, slen = 0, nlen, vlen, dlen;
    field_t *f;

    dbg_err_if(rs == NULL);
    dbg_err_if(pbuf == NULL);
    dbg_err_if(pcap == NULL);
    dbg_err_if(plen == NULL);

    /* the caller writes the body itself: its length must already be in
     * Content-Length for the connection to stay open */
    dbg_err_if(response_set_body_framing(rs, -1, 0));
    rs->header_sent = 1;

    /* status line "HTTP/1.x NNN desc\r\n" (none in CGI mode) */
    if(!rs->cgi)
    {
        dbg_err_if(rs->status < 0);
        desc = http_get_status_desc(rs->status);
        dlen = strlen(desc);
        /* "HTTP/1.x " + at most 20 digits + " " + desc + "\r\n" */
        dbg_err_if(dlen > STATUSSZ - 9 - 21 - 1 - 2);

        memcpy(status, "HTTP/1.x ", 9);
        status[7] = rs->http11 ? '1' : '0';
        slen = 9 + response_ultoa(status + 9, (unsigned long) rs->status);
        status[slen++] = ' ';
        memcpy(status + slen, desc, dlen);
        slen += dlen;
        memcpy(status + slen, "\r\n", 2);
        slen += 2;
    }

    /* "name: value\r\n" per field and the final "\r\n" */
    sz = slen + 2;
    for(f = NULL; (f = header_next_field(rs->header, NULL, f)) != NULL; )
        sz += strlen(f->name) + strlen(f->value) + 4;

    if(*pbuf && *pcap >= sz + extra)
        buf = *pbuf;
    else
        dbg_err_if((buf = u_malloc(sz + extra)) == NULL);

    memcpy(buf, status, slen);
    p = buf + slen;
    for(f = NULL; (f = header_next_field(rs->header, NULL, f)) != NULL; )
    {
        nlen = strlen(f->name);
        vlen = strlen(f->value);
        memcpy(p, f->name, nlen);
        p += nlen;
        memcpy(p, ": ", 2);
        p += 2;
        memcpy(p, f->value, vlen);
        p += vlen;
        memcpy(p, "\r\n", 2);
        p += 2;
    }
    memcpy(p, "\r\n", 2);

    if(buf != *pbuf)
    {
        U_FREE(*pbuf);
        *pbuf = buf;
        *pcap = sz + extra;
    }
    *plen = sz;

    return 0;
err:
    if(pbuf && buf != *pbuf)
        U_FREE(buf);
    return ~0;
}

/** 
 * \ingroup response
 * \brief   Print a response header
 *  
 * Print the header of \p rs
 *
 * \param rs        parameter \p rs description
 *  
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_print_header(response_t *rs)
{
    return response_print_header_to_io(rs, rs->io);
}


/**
 * \ingroup response
 * \brief   Set an header field of a response object
 *
 * Set field \p name to \p value in reponse object \p rs.
 *
 * \param rs     response object
 * \param name   field name
 * \param value  field value
 *
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_set_field(response_t *rs, const char *name, const char *value)
{
    return header_set_field(rs->header, name, value);
}


/**
 * \ingroup response
 * \brief   Remove an header field of a response object
 *
 * Remove the header field whose name is \p name
 *
 * \param rs     response object
 * \param name   field name
 *
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_del_field(response_t *rs, const char *name)
{
    field_t *f = NULL;
    
    f = header_get_field(rs->header, name);
    dbg_err_if(f == NULL);

    /* field found, delete it */
    dbg_err_if(header_del_field(rs->header, f));

    field_free(f);

    return 0;
err:
    return ~0;
}

/**
 * \ingroup response
 * \brief   Set the content type of a response to a mime type
 *
 * Set the \e Content-Type field of response \p rs to \p mime_type.
 *
 * \param rs         response object
 * \param mime_type  mime type
 *
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_set_content_type(response_t *rs, const char *mime_type)
{
    dbg_err_if(mime_type == NULL);

    dbg_err_if(header_set_field(rs->header, "Content-Type", mime_type));

    return 0;
err:
    return ~0;
}

/* the last date formatted by a caller: the same few dates (the current
 * second, a file's modification time) are formatted over and over */
typedef struct response_date_s
{
    int valid;
    time_t date;
    char buf[64];
} response_date_t;

static const char *response_format_date(response_date_t *cache, time_t date)
{
    if(!cache->valid || cache->date != date)
    {
        cache->valid = 0;
        dbg_err_if(u_tt_to_rfc822(cache->buf, date));
        cache->date = date;
        cache->valid = 1;
    }

    return cache->buf;
err:
    return NULL;
}

/**
 * \ingroup response
 * \brief   Set the date field in a response header
 *
 * Set the \e Date field of \p rs to \p date. 
 *
 * \param rs    response object
 * \param date  date value
 *
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_set_date(response_t *rs, time_t date)
{
    static response_date_t cache;

    dbg_err_if(header_set_field(rs->header, "Date",
                response_format_date(&cache, date)));

    return 0;
err:
    return ~0;
}

/**
 * \ingroup response
 * \brief   Set the last modified field in a response header
 *
 * Set the \e Last-Modified field of \p rs to \p mtime.
 *
 * \param rs     response object
 * \param mtime  last modified date value
 *
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_set_last_modified(response_t *rs, time_t mtime)
{
    static response_date_t cache;

    dbg_err_if(header_set_field(rs->header, "Last-Modified",
                response_format_date(&cache, mtime)));

    return 0;
err:
    return ~0;
}

/**
 * \ingroup response
 * \brief   Set the content length field of a response header
 *
 * Set the \e Content-Length field of \p rs to \p sz.
 *
 * \param rs  response object
 * \param sz  number of bytes in content
 *
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_set_content_length(response_t *rs, size_t sz)
{
    enum { BUFSZ = 64 };
    char buf[BUFSZ];

    (void) response_ultoa(buf, (unsigned long) sz);

    dbg_err_if(header_set_field(rs->header, "Content-Length", buf));

    return 0;
err:
    return ~0;
}

/** 
 * \ingroup response
 * \brief   Get the status of a response
 *  
 * Get the status of a response \p rs. For possible values of status refer to
 * response.h.
 *
 * \param rs  response object
 *  
 * \return
 *  - the status of the given \p rs
 */
int response_get_status(response_t *rs)
{
    return rs->status;
}

/**
 * \ingroup response
 * \brief   Get the header of a response
 *
 * Get the header of a response \p rs.
 *
 * \param rs    response object
 *
 * \return
 *  - the child header object of the given \p rs
 */
header_t* response_get_header(response_t *rs)
{
    return rs->header;
}

/**
 * \ingroup response
 * \brief   Get the I/O object of a response
 *
 * Get the I/O object of reponse \p rs.
 *  
 * \param rs  response object
 *      
 * \return
 *  - the I/O child object of the given \p rs
 */
io_t* response_io(response_t *rs)
{
    return rs->io;
}

/** 
 * \ingroup response
 * \brief   Redirect to a given url
 *  
 * Redirect to \e url by setting the \e Location field in response \p rs.
 *
 * \param rs    parameter \p rs description
 * \param url   parameter \p url description
 *  
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_redirect(response_t *rs, const char *url)
{
    field_t *field;

    /* send Location: with redirect status code */
    response_set_status(rs, HTTP_STATUS_MOVED_TEMPORARILY);

    dbg_err_if(field_create("Location", url, &field));

    header_add_field(rs->header, field); 

    return 0;
err:
    return ~0;
}

/** 
 * \ingroup response
 * \brief   Set the status of a response
 *  
 * Set the \p status of response \p rs. For possible values of status
 * refer to response.h.
 *
 * \param rs      parameter \p rs description
 * \param status  parameter \p status description
 *  
 * \return
 *  - \c 0  always
 */
int response_set_status(response_t *rs, int status)
{
    rs->status = status;

    return 0;
}

/*
 * \ingroup response
 * \brief   Bind the response to a given I/O object
 *  
 * Bind response \p rs to I/O object \p out.
 *
 * \param rs     
 * \param out  output I/O object
 *  
 * \return
 *  - \c 0  always
 */
int response_bind(response_t *rs, io_t *out)
{
    rs->io = out;

    return 0;
}

/*
 * \ingroup response
 * \brief   Create a response object
 *  
 * \param http  parameter \p http description
 * \param prs   parameter \p prs description
 *  
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_create(http_t *http, response_t **prs)
{
    response_t *rs = NULL;

    rs = u_zalloc(sizeof(response_t));
    dbg_err_if(rs == NULL);

    dbg_err_if(header_create(&rs->header));

    rs->http = http;

    *prs = rs;

    return 0;
err:
    if(rs->header)
        header_free(rs->header);
    if(rs)
        response_free(rs);
    return ~0;
}

/*
 * \ingroup response
 * \brief   Free a response object
 *  
 * \param rs response object
 *  
 * \return
 *  - \c 0  always
 */
int response_free(response_t *rs)
{
    if(rs->io)
        io_free(rs->io);

    if(rs->header)
        header_free(rs->header);

    U_FREE(rs);

    return 0;
}


/**
 * \ingroup response
 * \brief   Set the connection persistence of a response
 *
 * Called by the server before the response header is printed: \p keep_alive
 * asks for the connection to stay open after this response, \p http11 tells
 * that the client speaks HTTP/1.1 (so the body may be sent chunked).
 *
 * \param rs          response object
 * \param keep_alive  !0 to keep the connection open
 * \param http11      !0 if the request is HTTP/1.1
 *
 * \return nothing
 */
void response_set_keep_alive(response_t *rs, int keep_alive, int http11)
{
    rs->keep_alive = keep_alive ? 1 : 0;
    rs->http11 = http11 ? 1 : 0;
}

/**
 * \ingroup response
 * \brief   Tell if the connection may be kept open after a response
 *
 * \param rs  response object
 *
 * \return !0 if the response header has been sent and its body is delimited
 *         (Content-Length, chunked encoding or no body at all)
 */
int response_get_keep_alive(response_t *rs)
{
    return rs->keep_alive && rs->header_sent && rs->framed;
}

/**
 * \ingroup response
 * \brief   Tell if the response header has already been printed
 *
 * \param rs  response object
 *
 * \return !0 once the header has been printed
 */
int response_header_sent(response_t *rs)
{
    return rs->header_sent;
}

/* the header has been written by other means (a WebSocket handshake):
   nothing more is printed for this response */
void response_set_header_sent(response_t *rs)
{
    rs->header_sent = 1;
}

/**
 * \ingroup response
 * \brief   Tell if the response body is sent with chunked encoding
 *
 * \param rs  response object
 *
 * \return !0 if the body is chunked
 */
/**
 * \ingroup response
 * \brief   Send the response as it is written
 *
 * The header goes out with the first byte of the body, and every write
 * then reaches the client after an io_flush() of the response io (chunked
 * on HTTP/1.1; on HTTP/1.0 the connection is closed at the end). Used by
 * Server-Sent Events. Must be called before anything is printed.
 *
 * \param rs  response object
 *
 * \return \c 0 if successful, \c ~0 if the header has been sent already
 */
int response_set_streaming(response_t *rs)
{
    dbg_return_if (rs == NULL || rs->header_sent, ~0);

    rs->streaming = 1;

    return 0;
}

int response_is_streaming(response_t *rs)
{
    return rs ? rs->streaming : 0;
}

int response_is_chunked(response_t *rs)
{
    return rs->chunked;
}

/**
 * \ingroup response
 * \brief   Close the connection after this response
 *
 * Used when the response turns out not to be correctly delimited (e.g.
 * fewer bytes than its Content-Length could be sent).
 *
 * \param rs  response object
 *
 * \return nothing
 */
void response_close_connection(response_t *rs)
{
    rs->keep_alive = 0;
}

/**
 * \ingroup response
 * \brief   Tell if a response carries a body
 *
 * 1xx, 204 and 304 responses and replies to HEAD have no body.
 *
 * \param rs  response object
 *
 * \return !0 if the response has a body
 */
int response_has_body(response_t *rs)
{
    if(rs->method == HM_HEAD)
        return 0;

    return !((rs->status >= 100 && rs->status < 200) || 
            rs->status == HTTP_STATUS_NO_CONTENT || 
            rs->status == HTTP_STATUS_NOT_MODIFIED);
}


/**
 * \ingroup response
 * \brief   Decide how the end of the response body is signalled
 *
 * Called once, just before the header is printed. A persistent connection
 * needs a delimited body: \p len (if >= 0) is the exact body length and
 * becomes the Content-Length; otherwise, if \p can_chunk, an HTTP/1.1 body
 * is sent with chunked encoding. When neither applies the connection is
 * closed after the response. The Connection field is set accordingly.
 *
 * \param rs         response object
 * \param len        body length, or -1 if not known
 * \param can_chunk  !0 if the caller can chunk-encode the body
 *
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int response_set_body_framing(response_t *rs, ssize_t len, int can_chunk)
{
    char clen[32];

    dbg_return_if (rs == NULL, ~0);

    if(rs->framed)
        return 0;
    rs->framed = 1;

    if(rs->cgi)
        return 0;   /* the web server running us frames the response */

    /* the page asked to close the connection */
    if(header_has_token(rs->header, "Connection", "close"))
        rs->keep_alive = 0;

    /* the server owns the framing: drop any coding set by a page or CGI */
    while(response_get_field(rs, "Transfer-Encoding"))
        dbg_err_if(response_del_field(rs, "Transfer-Encoding"));

    if(!response_has_body(rs))
    {
        /* no body is sent (see rsfilter); 1xx and 204 must not even
         * announce one (a 304 or HEAD may report the size of the GET body) */
        if(rs->method != HM_HEAD && rs->status != HTTP_STATUS_NOT_MODIFIED)
            while(response_get_field(rs, "Content-Length"))
                dbg_err_if(response_del_field(rs, "Content-Length"));
    } else if(len >= 0) {
        /* the whole body is known: its measured length wins (it is usually
         * what the page set already, e.g. for a static file) */
        (void) response_ultoa(clen, (unsigned long) len);
        if(header_count_field(rs->header, "Content-Length") != 1 ||
                strcmp(response_get_field_value(rs, "Content-Length"), clen))
        {
            while(response_get_field(rs, "Content-Length"))
                dbg_err_if(response_del_field(rs, "Content-Length"));
            dbg_err_if(response_set_field(rs, "Content-Length", clen));
        }
    } else if(header_get_field(rs->header, "Content-Length") == NULL) {
        /* streamed body of unknown length */
        if(rs->http11 && can_chunk) {
            dbg_err_if(response_set_field(rs, "Transfer-Encoding", "chunked"));
            rs->chunked = 1;
        } else
            rs->keep_alive = 0;     /* the end of the body is the close */
    }

    if(rs->keep_alive)
    {
        /* HTTP/1.1 connections are persistent by default */
        if(!rs->http11)
            dbg_err_if(response_set_field(rs, "Connection", "keep-alive"));
    } else if(rs->http11)
        dbg_err_if(response_set_field(rs, "Connection", "close"));

    return 0;
err:
    return ~0;
}

/* return a field obj of the field named 'name' or NULL if the field does not 
   exist */
field_t* response_get_field(response_t *rs, const char *name)
{
    dbg_return_if (rs == NULL, NULL);
    dbg_return_if (name == NULL, NULL);

    return header_get_field(rs->header, name);
}

/* return the string value of the field named 'name' or NULL if the field does
   not exist */
const char* response_get_field_value(response_t *rs, const char *name)
{
    dbg_return_if (rs == NULL, NULL);
    dbg_return_if (name == NULL, NULL);

    return header_get_field_value(rs->header, name);
}
