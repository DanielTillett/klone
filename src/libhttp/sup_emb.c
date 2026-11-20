/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <u/libu.h>
#include <klin/supplier.h>
#include <klin/io.h>
#include <klin/ioprv.h>
#include <klin/page.h>
#include <klin/http.h>
#include <klin/emb.h>
#include <klin/codecs.h>
#include <klin/ses_prv.h>
#include <klin/rsfilter.h>
#include <klin/dypage.h>
#include "http_s.h"

static int supemb_is_valid_uri(http_t *h, request_t *rq, const char *uri, 
        size_t len, void **handle, time_t *mtime)
{
    embres_t *e;
    embfile_t *ef;
    char filename[U_FILENAME_MAX];

    dbg_err_if (uri == NULL);
    dbg_err_if (mtime == NULL);
    dbg_err_if (len + 1 > U_FILENAME_MAX);

    u_unused_args(h, rq);

    memcpy(filename, uri, len);
    filename[len] = '\0';

    if(emb_lookup(filename, &e) == 0)
    {   /* resource found */

        *mtime = 0; /* don't cache */
        if(e->type == ET_FILE)
        {
            ef = (embfile_t*)e;  

            if(ef->encrypted == 0)
                *mtime = ef->mtime;
        } 

        *handle = NULL;

        return 1;
    }

err:
    return 0; /* not found */
}

#ifdef SSL_ON
static int supemb_get_cipher_key(request_t *rq, response_t *rs, char *key, 
    size_t keysz)
{
    session_t *ss = NULL;
    http_t *http = NULL;
    session_opt_t *so;
    vars_t *vars;
    var_t *v;

    dbg_err_if (rq == NULL);
    dbg_err_if (rs == NULL);
    dbg_err_if (key == NULL);

    /* get session options */
    dbg_err_if((http = request_get_http(rq)) == NULL);
    dbg_err_if((so = http_get_session_opt(http)) == NULL);

    /* create/get the session */
    dbg_err_if(session_create(so, rq, rs, &ss));

    /* get variables list */
    vars = session_get_vars(ss);
    dbg_err_if(vars == NULL);

    v = vars_geti(vars, SESSION_KEY_VAR, 0);
    if(v == NULL)   /* set by a page written before the rename */
        v = vars_geti(vars, SESSION_KEY_VAR_OLD, 0);
    dbg_err_if(v == NULL); /* no such variable */

    dbg_err_if(var_get_value_size(v) > keysz);

    /* zero-out key array */
    memset(key, 0, keysz);

    /* set the key */
    memcpy(key, var_get_value(v), var_get_value_size(v));

    session_free(ss);

    return 0;
err:
    if(ss)
        session_free(ss);
    return ~0;
}
#endif /* SSL_ON */

static int supemb_static_set_header_fields(request_t *rq, response_t *rs, 
    embfile_t *e, int *sai)
{
    vhost_t *vhost;

    dbg_err_if (rq == NULL);
    dbg_err_if (rs == NULL);
    dbg_err_if (e == NULL);
    dbg_err_if (sai == NULL);

    dbg_err_if((vhost = request_get_vhost(rq)) == NULL);

    /* set header fields based on embfile_t struct */

    /* set content-type, last-modified and content-length*/
    dbg_err_if(response_set_content_type(rs, e->mime_type));
    dbg_err_if(response_set_last_modified(rs, e->mtime));
    dbg_err_if(response_set_content_length(rs, e->file_size));

    /* if the client can accept deflated content don't uncompress the 
       resource but send as it is (if enabled by config) */
    if(vhost->send_enc_deflate)
    {
        /* only zlib data is HTTP's "deflate" (older raw data is not) */
        if(e->comp == EMB_COMP_ZLIB &&
                (*sai = request_is_encoding_accepted(rq, "deflate")) != 0)
        {   /* we can send compressed responses */
            dbg_err_if(response_set_content_encoding(rs, "deflate"));
            dbg_err_if(response_set_content_length(rs, e->size));
            /*  u_dbg("sending deflated content"); */
        } 
    }

    return 0;
err:
    return ~0;
}

/* Conditional and range requests for embedded files (RFC 9110 13, 14).
 * The ETag is a digest of the source file made at build time; a file sent
 * as stored (deflated) is another representation, with its own ETag. Only
 * single byte ranges are served: a request for several gets the whole file
 * (200), which RFC 9110 allows. */
enum { SUPEMB_ETAG_SZ = 64 };

/* does the If-None-Match / If-Range list 'list' match 'etag'? (weak
 * comparison: a W/ prefix is ignored) */
static int supemb_etag_in(const char *list, const char *etag)
{
    size_t len = strlen(etag);
    const char *p = list;

    while(p && *p)
    {
        p += strspn(p, " \t,");
        if(*p == '*')
            return 1;
        if(!strncmp(p, "W/", 2))
            p += 2;
        if(!strncmp(p, etag, len) && (p[len] == '\0' || p[len] == ',' ||
                    p[len] == ' ' || p[len] == '\t'))
            return 1;
        p += strcspn(p, ",");
    }

    return 0;
}

/* parse a single "bytes=first-last", "bytes=first-" or "bytes=-suffix"
 * range of a 'size' byte file. Return 0 and the range, 1 if unsatisfiable,
 * -1 if the Range should be ignored (bad syntax, several ranges) */
static int supemb_parse_range(const char *v, size_t size, size_t *pfirst,
        size_t *plast)
{
    unsigned long long a = 0, b = 0;
    char *end;
    const char *p;
    int has_a, has_b;

    if(strncasecmp(v, "bytes=", 6))
        return -1;
    p = v + 6;
    p += strspn(p, " \t");
    if(strchr(p, ','))
        return -1;      /* several ranges: the whole file */

    if((has_a = (*p >= '0' && *p <= '9')))
    {
        a = strtoull(p, &end, 10);
        p = end;
    }
    if(*p++ != '-')
        return -1;
    if((has_b = (*p >= '0' && *p <= '9')))
    {
        b = strtoull(p, &end, 10);
        p = end;
    }
    p += strspn(p, " \t");
    if(*p != '\0' || (!has_a && !has_b) || (has_a && has_b && b < a))
        return -1;

    if(!has_a)
    {   /* the last b bytes */
        if(b == 0 || size == 0)
            return 1;
        *pfirst = b >= size ? 0 : size - (size_t) b;
        *plast = size - 1;
        return 0;
    }

    if(a >= size)
        return 1;
    *pfirst = (size_t) a;
    *plast = (!has_b || b >= size) ? size - 1 : (size_t) b;

    return 0;
}

/* a codec passing on only bytes [first, first + len) of what goes through
 * it: the range of a file stored compressed, after it is uncompressed */
typedef struct supemb_range_s
{
    codec_t codec;
    size_t first, len, off;
} supemb_range_t;

static ssize_t supemb_range_transform(codec_t *c, char *dst, size_t *dcount,
        const char *src, size_t src_sz)
{
    supemb_range_t *r = (supemb_range_t *) c;
    size_t skip = 0, n = 0;

    if(r->off < r->first)
        skip = U_MIN(src_sz, r->first - r->off);
    if(r->off + skip < r->first + r->len)
        n = U_MIN(U_MIN(src_sz - skip, r->first + r->len - r->off - skip),
                *dcount);
    else    /* past the range: drop the rest */
        skip = src_sz;

    memcpy(dst, src + skip, n);
    *dcount = n;
    r->off += skip + n;

    return (ssize_t) (skip + n);
}

static ssize_t supemb_range_flush(codec_t *c, char *dst, size_t *dcount)
{
    u_unused_args(c, dst);
    *dcount = 0;
    return CODEC_FLUSH_COMPLETE;
}

static int supemb_range_free(codec_t *c)
{
    U_FREE(c);
    return 0;
}

static int supemb_range_create(size_t first, size_t len, codec_t **pc)
{
    supemb_range_t *r;

    dbg_return_if ((r = u_zalloc(sizeof *r)) == NULL, ~0);

    r->first = first;
    r->len = len;
    r->codec.transform = supemb_range_transform;
    r->codec.flush = supemb_range_flush;
    r->codec.free = supemb_range_free;
    *pc = (codec_t *) r;

    return 0;
}

/* answer If-None-Match (304) and Range (206 or 416). Return 0 to send the
 * whole file, 1 when the response is complete (a 304 or 416, or a 206 with
 * *pfirst and *plen set) */
static int supemb_conditional(request_t *rq, response_t *rs, embfile_t *e,
        const char *etag, size_t *pfirst, size_t *plen)
{
    char buf[128];
    const char *v;
    size_t first = 0, last = 0;
    time_t t;
    int rc;

    if(etag == NULL)
        return 0;

    if((v = request_get_field_value(rq, "If-None-Match")) != NULL &&
            supemb_etag_in(v, etag))
    {
        dbg_err_if(response_set_status(rs, HTTP_STATUS_NOT_MODIFIED));
        return 1;
    }

    if(request_get_method(rq) != HM_GET ||
            (v = request_get_field_value(rq, "Range")) == NULL)
        return 0;

    /* If-Range: the range only if the file is still the one the client has
       part of (an ETag, or the exact Last-Modified date) */
    if((v = request_get_field_value(rq, "If-Range")) != NULL)
    {
        if(v[0] == '"' || !strncmp(v, "W/", 2))
        {
            if(strcmp(v, etag))
                return 0;   /* strong comparison only */
        } else if(u_httpdate_to_tt(v, &t) || t != e->mtime)
            return 0;
    }

    v = request_get_field_value(rq, "Range");
    if((rc = supemb_parse_range(v, e->file_size, &first, &last)) < 0)
        return 0;

    if(rc == 1)
    {
        dbg_err_if(u_snprintf(buf, sizeof buf, "bytes */%lu",
                    (unsigned long) e->file_size));
        dbg_err_if(response_set_field(rs, "Content-Range", buf));
        dbg_err_if(response_set_status(rs, HTTP_STATUS_RANGE_NOT_SATISFIABLE));
        dbg_err_if(response_set_content_length(rs, 0));
        return 1;
    }

    dbg_err_if(u_snprintf(buf, sizeof buf, "bytes %lu-%lu/%lu",
                (unsigned long) first, (unsigned long) last,
                (unsigned long) e->file_size));
    dbg_err_if(response_set_field(rs, "Content-Range", buf));
    dbg_err_if(response_set_status(rs, HTTP_STATUS_PARTIAL_CONTENT));
    dbg_err_if(response_set_content_length(rs, last - first + 1));
    *pfirst = first;
    *plen = last - first + 1;

    return 1;
err:
    return 0;
}

static int supemb_serve_static(request_t *rq, response_t *rs, embfile_t *e)
{
    codec_t *gzip = NULL, *decrypt = NULL, *range = NULL;
    char etag[SUPEMB_ETAG_SZ];
    const char *tag = NULL;
    size_t first = 0, len = 0;
    int sai = 0; /* send as is */
    int decrypting = 0, ec = ~0;
#ifdef SSL_ON
    char key[CODEC_CIPHER_KEY_BUFSZ];
#endif
    codec_t *rsf = NULL;

    dbg_return_if (rq == NULL, ~0);
    dbg_return_if (rs == NULL, ~0);
    dbg_return_if (e == NULL, 0);

    /* create a response filter and attach it to the response io */
    dbg_err_if(response_filter_create(rq, rs, NULL, &rsf));
    dbg_err_if(io_codec_add_tail(response_io(rs), rsf));
    rsf = NULL;

    /* set HTTP header based on 'e' (we have the cipher key here) */
    dbg_err_if(supemb_static_set_header_fields(rq, rs, e, &sai));

    /* the ETag of what is sent: the deflated data is another
       representation. Ranges of the file as stored are not served */
    if(e->etag && !e->encrypted)
    {
        if(sai)
        {   /* "hex" -> "hex-deflate" */
            dbg_err_if(u_snprintf(etag, sizeof etag, "%.*s-deflate\"",
                        (int) strlen(e->etag) - 1, e->etag));
            tag = etag;
        } else {
            tag = e->etag;
            dbg_err_if(response_set_field(rs, "Accept-Ranges", "bytes"));
        }
        dbg_err_if(response_set_field(rs, "ETag", tag));
    }

    /* If-None-Match (304) and Range (206, 416) */
    if(supemb_conditional(rq, rs, e, sai ? NULL : tag, &first, &len) &&
            len == 0)
        return 0;   /* 304 or 416: no body */
    if(sai && tag && request_get_field_value(rq, "If-None-Match") &&
            supemb_etag_in(request_get_field_value(rq, "If-None-Match"), tag))
    {
        dbg_err_if(response_set_status(rs, HTTP_STATUS_NOT_MODIFIED));
        return 0;
    }

    /* if this is a HEAD request print the header and exit */
    if(request_get_method(rq) == HM_HEAD)
        return 0; /* just the header is requested */

#ifdef HAVE_LIBZ
    /* if needed apply a gzip codec to uncompress content data */
    if(e->comp && !sai)
        dbg_err_if(codec_gzip_create(e->comp == EMB_COMP_ZLIB ?
                    ZLIB_UNCOMPRESS : GZIP_UNCOMPRESS, &gzip));
#endif

#ifdef SSL_ON
    /* if the resource is encrypted unencrypt it using the key stored in 
       SESSION_KEY_VAR session variable */
    if(e->encrypted)
    {
        /* if the content is encrypted and there's no key then exit */
        if(supemb_get_cipher_key(rq, rs, key, sizeof(key)))
        {   
            dbg_err_if(response_set_status(rs, HTTP_STATUS_EXT_KEY_NEEDED));

            /* clean up and exit with no error to propagate the status code */
            ec = 0;

            dbg_err("cipher key not found, aborting");
        }

        /* do not cache encrypted content */
        response_disable_caching(rs);

        dbg_err_if(codec_cipher_create(CIPHER_DECRYPT, KC_AES_256_CBC,
                    (unsigned char *)key, NULL, &decrypt));
        /* delete the key from the stack */
        memset(key, 0, CODEC_CIPHER_KEY_BUFSZ);
    } 
#endif

    /* a range of a compressed file: cut it from the uncompressed data
       (the gzip codec, added in front, runs first) */
    if(len && gzip)
    {
        dbg_err_if(supemb_range_create(first, len, &range));
        dbg_err_if(io_codec_add_head(response_io(rs), range));
        range = NULL;
    }

    if(gzip)
    {   /* set gzip filter */
        dbg_err_if(io_codec_add_head(response_io(rs), gzip));
        gzip = NULL; /* io_t owns it after io_codec_add_tail */
    }

    if(decrypt)
    {   /* set decrypt filter */
        dbg_err_if(io_codec_add_head(response_io(rs), decrypt));
        decrypt = NULL; /* io_t owns it after io_codec_add_tail */
        decrypting = 1;
    }

    /* print out page content (the header will be autoprinted by the
       response io filter); a range of uncompressed data directly */
    if(len && !e->comp)
        dbg_err_if(io_write(response_io(rs), (const char*)e->data + first,
                    len) < (ssize_t)len);
    else
        dbg_err_if(io_write(response_io(rs), (const char*)e->data, e->size)
            < (ssize_t)e->size);

    /* remove and free the gzip/decrypt codecs (if they have been set) */
    dbg_err_if(io_codecs_remove(response_io(rs))); 

    return 0;
err:
    if(decrypting) /* usually wrong key given */
    {
        dbg_if(response_set_status(rs, HTTP_STATUS_EXT_KEY_NEEDED)); 
        ec = 0;
    }
    /* remove codecs and rs filter */
    dbg_if(io_codecs_remove(response_io(rs))); 
    if(decrypt)
        codec_free(decrypt);
    if(gzip)
        codec_free(gzip);
    if(range)
        codec_free(range);
    return ec;
}

static int supemb_serve_dynamic(request_t *rq, response_t *rs, embpage_t *e)
{
    dypage_args_t args;

    args.rq = rq;
    args.rs = rs;
    args.ss = NULL; /* dypage_serve will set it before calling args.fun() */
    args.fun = e->fun;
    args.opaque = NULL;

    dbg_err_if(dypage_serve(&args));

    return 0;
err:
    return ~0;
}

static int supemb_serve(request_t *rq, response_t *rs)
{
    const char *file_name;
    embres_t *e;

    dbg_err_if (rq == NULL);
    dbg_err_if (rs == NULL);
    
    file_name = request_get_resolved_filename(rq);
    dbg_ifb(file_name == NULL || emb_lookup(file_name, &e))
    {
        response_set_status(rs, HTTP_STATUS_NOT_FOUND); 
        return 0;
    }

    /* u_dbg("serving %s", e->filename); */

    switch(e->type)
    {
    case ET_FILE:
        dbg_err_if(supemb_serve_static(rq, rs, (embfile_t*)e));
        break;
    case ET_PAGE:
        dbg_err_if(supemb_serve_dynamic(rq, rs, (embpage_t*)e));
        break;
    default:
        dbg_err_if("unknown res type");
    }

    return 0;
err:
    return ~0;
}

static int supemb_init(void)
{
    return 0;
}

static void supemb_term(void)
{
    return;
}

supplier_t sup_emb = {
    "embedded content supplier",
    supemb_init,
    supemb_term,
    supemb_is_valid_uri,
    supemb_serve
};

