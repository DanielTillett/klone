/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <u/libu.h>
#include <klin/request.h>
#include <klin/response.h>
#include <klin/session.h>
#include <klin/utils.h>
#include <klin/io.h>
#include <klin/codec.h>
#include <klin/http.h>
#include <klin/response.h>
#include <klin/rsfilter.h>
#include <klin/ses_prv.h>

/* this filter prints the HTTP header before any body part of the web page.
 * the first RFBUFSZ bytes (at most) of the response will be buffered to
 * postpone the header printing (the header can be modified until filter flush)
 *
 * the filter also delimits the body so the connection can be kept open: a
 * body that fits in the buffer gets a Content-Length, a longer one is sent
 * with chunked encoding (HTTP/1.1 only, see response_set_body_framing)
 */

enum {
    RFS_BUFFERING,
    RFS_FLUSHING
};

enum {
    RF_CHUNK_MAX = RFBUFSZ,     /* max data bytes per chunk                  */
    RF_CHUNK_EXTRA = 16,        /* size line ("1000\r\n") and trailing CRLF  */
    RF_HBUF_KEEP = 16384        /* max header buffer kept for the next one   */
};

struct response_filter_s
{
    codec_t codec;          /* must be the first item in the struct */
    request_t *rq;
    response_t *rs;
    session_t *ss;
    int state, feeded;
    char *ptr;
    size_t off;
    char *head;             /* header and buffered body, ready to be sent */
    size_t hlen, hoff;      /* ... its length and the bytes already sent  */
    int chunked;            /* chunk-encode the body                      */
    int last_chunk;         /* the terminating chunk has been queued      */
    int no_body;            /* HEAD, 1xx, 204, 304: the body is dropped   */
    int limited;            /* the header announced a Content-Length ...  */
    size_t limit, sent;     /* ... of 'limit' bytes; 'sent' so far        */
    size_t clen, coff;

    /* the buffers must be the last items: they are not zeroed on creation */
    char buf[RFBUFSZ];
    char cbuf[RF_CHUNK_MAX + RF_CHUNK_EXTRA];  /* pending encoded chunk    */
    char *hbuf;             /* memory of 'head', kept when the filter is   */
    size_t hcap;            /* reused (header + body is too big for the    */
                            /* allocator's fast paths)                     */
};

/* the filter of the last response, kept for the next one: at 8 KB it is
 * too big for the allocator's fast paths */
static response_filter_t *rf_spare = NULL;

/* queue the header followed by the buffered body (if any) */
static int rf_init_head(response_filter_t *rf)
{
    size_t body;
    char *p;
    int n;

    dbg_err_if (rf == NULL);

    body = (!rf->no_body && rf->off) ? rf->off + RF_CHUNK_EXTRA : 0;

    dbg_err_if(response_format_header_reuse(rf->rs, body, &rf->hbuf, &rf->hcap,
                &rf->hlen));
    rf->head = rf->hbuf;
    rf->hoff = 0;

    if(body)
    {
        p = rf->head + rf->hlen;
        if(rf->chunked)
        {
            n = snprintf(p, RF_CHUNK_EXTRA, "%lx\r\n", (unsigned long) rf->off);
            dbg_err_if(n < 0 || n >= RF_CHUNK_EXTRA - 2);
            p += n;
        }
        memcpy(p, rf->buf, rf->off);
        p += rf->off;
        if(rf->chunked)
        {
            memcpy(p, "\r\n", 2);
            p += 2;
        }
        rf->hlen = (size_t) (p - rf->head);
    }

    return 0;
err:
    return ~0;
}

/* stop buffering: decide the body framing and queue the header and the
 * buffered body; 'final' if the whole body is in rf->buf */
static int rf_start(response_filter_t *rf, int final)
{
    const char *clen;

    rf->state = RFS_FLUSHING;

    /* the status is final now: drop the body of a bodyless response */
    if((rf->no_body = !response_has_body(rf->rs)) != 0)
        rf->off = 0;

    dbg_err_if(response_set_body_framing(rf->rs,
                final ? (ssize_t) rf->off : -1, !final));
    rf->chunked = response_is_chunked(rf->rs);

    /* never send more than the announced Content-Length, and close the
       connection if less is sent (see rf_flush) */
    if(!rf->no_body && !rf->chunked &&
            (clen = response_get_field_value(rf->rs, "Content-Length")))
    {
        rf->limited = 1;
        rf->limit = (size_t) strtoul(clen, NULL, 10);
        if(rf->off > rf->limit)
        {
            rf->off = rf->limit;
            response_close_connection(rf->rs);
        }
        rf->sent = rf->off;
    }

    /* queue the header and rf->buf */
    dbg_err_if(rf_init_head(rf));

    return 0;
err:
    return ~0;
}

/* encode up to RF_CHUNK_MAX bytes of src as the pending chunk (an empty src
 * queues the terminating chunk); return the number of bytes consumed */
static size_t rf_queue_chunk(response_filter_t *rf, const char *src, size_t sz)
{
    int n;

    sz = U_MIN(sz, RF_CHUNK_MAX);

    n = snprintf(rf->cbuf, RF_CHUNK_EXTRA, "%lx\r\n", (unsigned long) sz);
    memcpy(rf->cbuf + n, src, sz);
    memcpy(rf->cbuf + n + sz, "\r\n", 2);

    rf->clen = n + sz + 2;
    rf->coff = 0;

    return sz;
}

/* copy queued output (header block first, then the pending chunk) to dst;
 * return the number of bytes copied (0 if nothing is queued) */
static ssize_t rf_drain(response_filter_t *rf, char *dst, size_t dsz)
{
    ssize_t c;

    if(rf->head)
    {
        if(rf->hoff < rf->hlen)
        {
            c = U_MIN(dsz, rf->hlen - rf->hoff);
            memcpy(dst, rf->head + rf->hoff, c);
            rf->hoff += c;
            return c;
        }

        /* all sent (the memory stays in rf->hbuf) */
        rf->head = NULL;
    }

    if(rf->coff < rf->clen)
    {
        c = U_MIN(dsz, rf->clen - rf->coff);
        memcpy(dst, rf->cbuf + rf->coff, c);
        rf->coff += c;
        return c;
    }

    return 0;
}

static ssize_t rf_flush(codec_t *codec, char *dst, size_t *dcount)
{
    response_filter_t *rf = (response_filter_t*)codec;
    ssize_t c;

    dbg_err_if (codec == NULL);
    dbg_err_if (dst == NULL);
    dbg_err_if (dcount == NULL);

    /* the whole body is in rf->buf: print header and body */
    if(rf->state == RFS_BUFFERING)
        dbg_err_if(rf_start(rf, 1));

    dbg_err_if((c = rf_drain(rf, dst, *dcount)) < 0);

    /* fewer bytes than announced: the client would wait for the rest */
    if(rf->limited && rf->sent < rf->limit)
        response_close_connection(rf->rs);

    /* end a chunked body with the zero-length chunk */
    if(c == 0 && rf->chunked && !rf->last_chunk)
    {
        rf->last_chunk = 1;
        (void) rf_queue_chunk(rf, "", 0);
        dbg_err_if((c = rf_drain(rf, dst, *dcount)) < 0);
    }

    if(c > 0)
    {
        *dcount = c;
        return CODEC_FLUSH_CHUNK;
    }

    *dcount = 0;
    return CODEC_FLUSH_COMPLETE;
err:
    return -1;
}

static ssize_t rf_transform(codec_t *codec,
        char *dst, size_t *dcount,
        const char *src, size_t src_sz)
{
    response_filter_t *rf = (response_filter_t*)codec;
    size_t max;
    ssize_t c;

    dbg_err_if (codec == NULL);
    dbg_err_if (dst == NULL);
    dbg_err_if (dcount == NULL);
    dbg_err_if (src == NULL);

    rf->feeded = 1;

    /* if this's a HEAD request don't print the body of the page */
    if(response_get_method(rf->rs) == HM_HEAD || rf->no_body)
    {
        *dcount = 0;    /* zero output byte written */
        return src_sz;  /* all input bytes consumed */
    }

    if(rf->state == RFS_BUFFERING)
    {
        /* buffered to measure the body, unless it is streamed */
        if(rf->off + src_sz < RFBUFSZ && !response_is_streaming(rf->rs))
        {
            memcpy(rf->buf + rf->off, src, src_sz);
            rf->off += src_sz;
            *dcount = 0;    /* zero output byte written */
            return src_sz;  /* src_sz input byte consumed */
        } else {
            /* here's the last chance to modify HTTP header so, if not already
               set, add a session ID to the cookie list */
            if(rf->ss && strlen(rf->ss->id) == 0)
                dbg_err_if(session_priv_set_id(rf->ss, NULL));

            /* the buffer is full, print the header and flush the buffer */
            dbg_err_if(rf_start(rf, 0));
        }
    }

    /* send queued output first */
    dbg_err_if((c = rf_drain(rf, dst, *dcount)) < 0);
    if(c > 0)
    {
        *dcount = c;
        return 0;       /* zero input byte consumed */
    }

    if(rf->chunked)
    {
        /* encode the next block as a chunk and start sending it */
        max = rf_queue_chunk(rf, src, src_sz);
        dbg_err_if((c = rf_drain(rf, dst, *dcount)) < 0);
        *dcount = c;
        return max;
    }

    /* the body is the whole Content-Length: drop anything after it */
    if(rf->limited && rf->sent >= rf->limit)
    {
        response_close_connection(rf->rs);
        *dcount = 0;
        return src_sz;
    }

    /* copyout the next data block */
    max = U_MIN(*dcount, src_sz);
    if(rf->limited)
        max = U_MIN(max, rf->limit - rf->sent);
    memcpy(dst, src, max);
    rf->sent += max;
    *dcount = max;
    return max;
err:
    return -1;
}

/* once the header (and any pending chunk) is out, plain body bytes go to
 * the connection unchanged: the io can write them directly */
static size_t rf_passthru(codec_t *codec, size_t src_sz)
{
    response_filter_t *rf = (response_filter_t*)codec;
    size_t n = src_sz;

    if(rf->state != RFS_FLUSHING || rf->chunked || rf->no_body ||
            response_get_method(rf->rs) == HM_HEAD ||
            (rf->head && rf->hoff < rf->hlen) || rf->coff < rf->clen)
        return 0;

    if(rf->limited)
    {
        if(rf->sent >= rf->limit)
            return 0;   /* rf_transform() drops the excess */
        n = U_MIN(n, rf->limit - rf->sent);
        rf->sent += n;
    }

    rf->feeded = 1;

    return n;
}

static int rf_free(codec_t *codec)
{
    response_filter_t *rf;

    dbg_return_if (codec == NULL, 0);   /* it's ok */

    rf = (response_filter_t*)codec;

    if(rf_spare == NULL)
    {
        /* don't keep the memory of an unusually large header */
        if(rf->hcap > RF_HBUF_KEEP)
        {
            U_FREE(rf->hbuf);
            rf->hcap = 0;
        }
        rf_spare = rf;
    } else {
        U_FREE(rf->hbuf);
        U_FREE(rf);
    }

    return 0;
}

int response_filter_feeded(codec_t *codec)
{
    response_filter_t *rf;

    dbg_return_if (codec == NULL, 0);   /* it's ok */

    rf = (response_filter_t*)codec;

    return rf->feeded; /* 1 if at least 1 byte has been written */
}

int response_filter_create(request_t *rq, response_t *rs, session_t *ss,
    codec_t **prf)
{
    response_filter_t *rf = NULL;

    dbg_err_if (rs == NULL);
    dbg_err_if (prf == NULL);

    /* zero all but the (8 KB of) buffers */
    if((rf = rf_spare) != NULL)
        rf_spare = NULL;
    else
    {
        dbg_err_if((rf = u_malloc(sizeof(response_filter_t))) == NULL);
        rf->hbuf = NULL;
        rf->hcap = 0;
    }
    memset(rf, 0, offsetof(response_filter_t, buf));

    rf->rq = rq;
    rf->rs = rs;
    rf->ss = ss;
    rf->codec.transform = rf_transform;
    rf->codec.flush = rf_flush;
    rf->codec.free = rf_free;
    rf->codec.passthru = rf_passthru;
    rf->ptr = rf->buf;

    *prf = (codec_t*)rf;

    return 0;
err:
    U_FREE(rf);
    return ~0;
}
