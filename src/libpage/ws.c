/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* WebSockets (RFC 6455, doc/WEBSOCKET). After the handshake the page owns
 * the connection: frames are read and written on it directly, outside the
 * response filter, and it is closed when the page ends. Waiting is done
 * in ws_wait() with poll(2) (the client socket, a descriptor of the page's
 * own, the timer); reading a frame and writing one each have a timeout, so
 * a client that stops half way cannot hold the worker. */

#include "klin_conf.h"
#include <errno.h>
#include <string.h>
#include <time.h>
#ifndef OS_WIN
#include <poll.h>
#endif
#include <u/libu.h>
#include <klin/io.h>
#include <klin/ws.h>
#include <klin/timer.h>
#include <klin/http.h>
#include <klin/crypto.h>
#include <klin/conntab.h>
#include <klin/utils.h>

enum {
    WS_IO_TIMEOUT = 30,             /* s to read or write one frame        */
    WS_MAX_MESSAGE = 1024 * 1024,   /* default largest message received    */
    WS_CLOSE_WAIT = 2000,           /* ms to wait for the close reply      */

    /* opcodes */
    WS_OP_CONT = 0x0, WS_OP_TEXT = 0x1, WS_OP_BINARY = 0x2,
    WS_OP_CLOSE = 0x8, WS_OP_PING = 0x9, WS_OP_PONG = 0xA,

    /* close codes */
    WS_CLOSE_NORMAL = 1000, WS_CLOSE_PROTOCOL = 1002, WS_CLOSE_DATA = 1007,
    WS_CLOSE_TOO_BIG = 1009, WS_CLOSE_ERROR = 1011
};

static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

struct ws_s
{
    request_t *rq;
    io_t *io;               /* the connection                             */
    char *msg;              /* the message being received or delivered    */
    size_t len, cap;
    int msg_type;           /* its type, 0 when none is in progress       */
    size_t max;             /* largest message accepted                   */
    int close_sent;         /* our close frame has been sent              */
    int ended;              /* the connection is over (closed or failed)  */
    char protocol[64];      /* the subprotocol chosen, "" if none         */
};

static int ws_cb_timeout(talarm_t *al, void *arg)
{
    u_unused_args(al);

    warn("WebSocket client stalled, connection closed");
    io_close((io_t *) arg);

    return 0;
}

/* send one frame (unmasked, as from a server) within WS_IO_TIMEOUT */
static int ws_send_frame(ws_t *ws, int op, const char *data, size_t len)
{
    unsigned char h[10];
    size_t hl = 2, i;
    talarm_t *al = NULL;

    h[0] = (unsigned char) (0x80 | op);    /* FIN: never fragmented here */
    if(len < 126)
        h[1] = (unsigned char) len;
    else if(len <= 0xFFFF)
    {
        h[1] = 126;
        h[2] = (unsigned char) (len >> 8);
        h[3] = (unsigned char) len;
        hl = 4;
    } else {
        h[1] = 127;
        for(i = 0; i < 8; ++i)
            h[2 + i] = (unsigned char) ((unsigned long long) len >> (56 - 8 * i));
        hl = 10;
    }

    dbg_err_if(timerm_add(WS_IO_TIMEOUT, ws_cb_timeout, ws->io, &al));
    nop_err_if(io_write(ws->io, (const char *) h, hl) < (ssize_t) hl);
    nop_err_if(len && io_write(ws->io, data, len) < (ssize_t) len);
    nop_err_if(io_flush(ws->io));
    timerm_del(al);

    return 0;
err:
    if(al)
        timerm_del(al);
    return ~0;
}

/* send a close frame with 'code' (once) */
static int ws_send_close(ws_t *ws, int code, const char *reason)
{
    char body[125];
    size_t rl = reason ? U_MIN(strlen(reason), sizeof body - 2) : 0;

    if(ws->close_sent)
        return 0;
    ws->close_sent = 1;

    body[0] = (char) (code >> 8);
    body[1] = (char) (code & 0xFF);
    if(rl)
        memcpy(body + 2, reason, rl);

    return ws_send_frame(ws, WS_OP_CLOSE, body, 2 + rl);
}

/* is 'len' bytes at 's' well-formed UTF-8 (no overlong forms, surrogates
 * or code points past U+10FFFF)? */
static int ws_utf8_ok(const unsigned char *s, size_t len)
{
    size_t i = 0, n, k;
    unsigned long cp;

    while(i < len)
    {
        if(s[i] < 0x80)
        {
            ++i;
            continue;
        }
        if(s[i] >= 0xC2 && s[i] <= 0xDF)
            n = 1, cp = s[i] & 0x1F;
        else if(s[i] >= 0xE0 && s[i] <= 0xEF)
            n = 2, cp = s[i] & 0x0F;
        else if(s[i] >= 0xF0 && s[i] <= 0xF4)
            n = 3, cp = s[i] & 0x07;
        else
            return 0;
        if(len - i <= n)
            return 0;       /* cut short */
        for(k = 1; k <= n; ++k)
        {
            if((s[i + k] & 0xC0) != 0x80)
                return 0;
            cp = (cp << 6) | (s[i + k] & 0x3F);
        }
        if((n == 2 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) ||
                (n == 3 && (cp < 0x10000 || cp > 0x10FFFF)))
            return 0;
        i += n + 1;
    }

    return 1;
}

#ifdef SSL_OPENSSL
/* Sec-WebSocket-Accept: base64(SHA-1(key GUID)) */
static int ws_accept_key(const char *key, char *out, size_t size)
{
    unsigned char md[KC_MD_MAX];
    size_t mdlen = 0;
    char buf[128];

    dbg_err_if(u_snprintf(buf, sizeof buf, "%s%s", key, WS_GUID));
    dbg_err_if(kc_digest(KC_SHA1, buf, strlen(buf), md, &mdlen));

    return u_b64_encode(md, mdlen, out, size);
err:
    return ~0;
}
#endif

/* does the page's Origin (if any) belong to the Host the client asked? */
static int ws_same_origin(request_t *rq)
{
    const char *origin = request_get_field_value(rq, "Origin"),
          *host = request_get_field_value(rq, "Host"), *p;

    if(origin == NULL)
        return 1;   /* not a browser: no cross-site page to worry about */
    if(host == NULL || (p = strstr(origin, "://")) == NULL)
        return 0;

    return !strcasecmp(p + 3, host);
}

/* the first of the server's protocols the client offers, or NULL */
static const char *ws_choose_protocol(request_t *rq, const char *protocols,
        char *out, size_t size)
{
    const char *p, *e;
    size_t n;

    for(p = protocols; p && *p; p = e)
    {
        p += strspn(p, " \t,");
        e = p + strcspn(p, " \t,");
        if((n = (size_t) (e - p)) == 0 || n >= size)
            continue;
        memcpy(out, p, n);
        out[n] = '\0';
        if(header_has_token(request_get_header(rq), "Sec-WebSocket-Protocol",
                    out))
            return out;
    }

    return NULL;
}

/* refuse the upgrade with 'status' (the page's response is then sent) */
static int ws_refuse(response_t *rs, int status)
{
    (void) response_set_status(rs, status);
    if(status == HTTP_STATUS_UPGRADE_REQUIRED)
        (void) response_set_field(rs, "Sec-WebSocket-Version", "13");
    return ~0;
}

/**
 * \brief   Accept a WebSocket connection
 *
 * Check the client's handshake and answer it (101 Switching Protocols).
 * The page must not have printed anything. On failure the response status
 * is set (400, 403 for another site's page, 426 for another protocol
 * version, 501 without OpenSSL) and the page should just end.
 *
 * \param rq         the request
 * \param rs         the response
 * \param protocols  subprotocols the page speaks, in order of preference
 *                   (blank or comma separated), or \c NULL
 * \param flags      ::WS_ANY_ORIGIN to accept pages of other sites
 * \param pws        the connection, to free with ws_free()
 *
 * \return \c 0 if the connection is upgraded, \c ~0 otherwise
 */
int ws_accept(request_t *rq, response_t *rs, const char *protocols, int flags,
        ws_t **pws)
{
    unsigned char raw[64];
    char accept[64], chosen[64];
    const char *key, *v, *proto = NULL;
    size_t rawlen = sizeof raw;
    ws_t *ws = NULL;
    io_t *io;

    dbg_return_if (rq == NULL || rs == NULL || pws == NULL, ~0);

#ifndef SSL_OPENSSL
    u_unused_args(protocols, flags, raw, accept, chosen, key, v, proto, rawlen,
            ws, io);
    return ws_refuse(rs, HTTP_STATUS_NOT_IMPLEMENTED);
#else
    /* a GET asking for the upgrade, version 13, with a 16-byte key */
    if(request_get_method(rq) != HM_GET ||
            strcmp(request_get_protocol(rq), "HTTP/1.1") ||
            !header_has_token(request_get_header(rq), "Upgrade", "websocket") ||
            !header_has_token(request_get_header(rq), "Connection", "upgrade"))
        return ws_refuse(rs, HTTP_STATUS_BAD_REQUEST);
    if((v = request_get_field_value(rq, "Sec-WebSocket-Version")) == NULL ||
            strcmp(v, "13"))
        return ws_refuse(rs, HTTP_STATUS_UPGRADE_REQUIRED);
    if((key = request_get_field_value(rq, "Sec-WebSocket-Key")) == NULL ||
            strlen(key) != 24 ||
            klin_b64_decode(key, strlen(key), raw, &rawlen) || rawlen != 16)
        return ws_refuse(rs, HTTP_STATUS_BAD_REQUEST);

    /* a page of another site must not reach the user's connection with
       the user's cookies (cross-site WebSocket hijacking) */
    if(!(flags & WS_ANY_ORIGIN) && !ws_same_origin(rq))
        return ws_refuse(rs, HTTP_STATUS_FORBIDDEN);

    /* max_streams of them are open: try again later */
    if(conntab_stream())
    {
        (void) response_set_field(rs, "Retry-After", "5");
        return ws_refuse(rs, HTTP_STATUS_SERVICE_UNAVAILABLE);
    }

    dbg_err_if(ws_accept_key(key, accept, sizeof accept));
    if(protocols)
        proto = ws_choose_protocol(rq, protocols, chosen, sizeof chosen);

    dbg_err_if((ws = u_zalloc(sizeof *ws)) == NULL);
    ws->rq = rq;
    ws->io = io = request_io(rq);
    ws->max = WS_MAX_MESSAGE;
    if(proto)
        (void) u_strlcpy(ws->protocol, proto, sizeof ws->protocol);

    /* from here the connection is the page's: drop the response filter
       (nothing has been sent), no longer stop reads at the request body,
       and close the connection after the page */
    dbg_err_if(io_codecs_discard(io));
    io_set_read_limit(io, -1);
    response_close_connection(rs);
    response_set_header_sent(rs);
    (void) response_set_status(rs, HTTP_STATUS_SWITCHING_PROTOCOLS);

    nop_err_if(io_printf(io, "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n%s%s%s\r\n", accept,
                proto ? "Sec-WebSocket-Protocol: " : "", proto ? proto : "",
                proto ? "\r\n" : "") < 0);
    nop_err_if(io_flush(io));

    *pws = ws;

    return 0;
err:
    if(ws)
        ws_free(ws);
    return ~0;
#endif
}

/* data that has arrived but not been read through the io yet */
static int ws_buffered(ws_t *ws)
{
    return io_pending(ws->io) > 0;
}

static long long ws_now_ms(void)
{
    struct timespec ts;

    (void) clock_gettime(CLOCK_MONOTONIC, &ts);

    return (long long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/**
 * \brief   Wait for a message, a descriptor of the page's, or a timeout
 *
 * \param ws   the connection
 * \param fd   a descriptor to wait for too (-1 for none)
 * \param ms   milliseconds to wait at most (-1: no limit)
 *
 * \return ::WS_MESSAGE (call ws_recv()), ::WS_READY (\p fd is readable),
 *         ::WS_TIMEOUT or ::WS_CLOSED
 */
int ws_wait(ws_t *ws, int fd, int ms)
{
#ifdef OS_WIN
    u_unused_args(ws, fd, ms);
    return WS_CLOSED;
#else
    struct pollfd p[2];
    long long end = ms < 0 ? -1 : ws_now_ms() + ms, left;
    int n, rc, t, cfd;

    dbg_return_if (ws == NULL, WS_CLOSED);

    for(;;)
    {
        if(ws->ended)
            return WS_CLOSED;
        if(ws_buffered(ws))
            return WS_MESSAGE;

        t = timerm_run();
        if((cfd = io_get_fd(ws->io)) < 0)
            return WS_CLOSED;

        p[0].fd = cfd;
        p[0].events = POLLIN;
        p[0].revents = 0;
        n = 1;
        if(fd >= 0)
        {
            p[1].fd = fd;
            p[1].events = POLLIN;
            p[1].revents = 0;
            n = 2;
        }

        if(end >= 0)
        {
            if((left = end - ws_now_ms()) <= 0)
                return WS_TIMEOUT;
            if(t < 0 || left < t)
                t = (int) U_MIN(left, 0x7fffffff);
        }

        rc = poll(p, (nfds_t) n, t);
        if(rc < 0 && errno == EINTR)
            continue;
        if(rc < 0)
            return WS_CLOSED;

        if(p[0].revents)
            return WS_MESSAGE;      /* a frame, or the close: ws_recv() */
        if(n == 2 && p[1].revents)
            return WS_READY;
    }
#endif
}

/* read exactly 'len' bytes of a frame */
static int ws_read(ws_t *ws, void *buf, size_t len)
{
    return (len && io_read(ws->io, buf, len) != (ssize_t) len) ? ~0 : 0;
}

/* make room for 'more' bytes of message */
static int ws_grow(ws_t *ws, size_t more)
{
    size_t cap;
    char *m;

    /* there is always a buffer, even for an empty first message: it ends
       with a NUL (found by fuzzing: an empty message wrote through NULL) */
    if(ws->msg != NULL && ws->len + more <= ws->cap)
        return 0;
    cap = U_MAX(ws->cap * 2, ws->len + more);
    dbg_err_if((m = u_realloc(ws->msg, cap + 1)) == NULL);
    ws->msg = m;
    ws->cap = cap;

    return 0;
err:
    return ~0;
}

/* read one frame and act on it: return 0 when a whole data message is in
 * ws->msg, WS_AGAIN after a control frame or a part of a message,
 * WS_CLOSED when the connection ends */
static int ws_read_frame(ws_t *ws)
{
    unsigned char h[2], ext[8], mask[4];
    unsigned long long plen;
    char ctl[125];
    char *dst;
    size_t i, n;
    int op, fin, code, rc = WS_AGAIN;
    talarm_t *al = NULL;

    /* a frame must arrive whole within WS_IO_TIMEOUT */
    dbg_err_if(timerm_add(WS_IO_TIMEOUT, ws_cb_timeout, ws->io, &al));

    nop_err_if(ws_read(ws, h, 2));
    fin = h[0] & 0x80;
    op = h[0] & 0x0F;
    plen = h[1] & 0x7F;

    /* no extension was agreed: the RSV bits are 0; a client masks */
    if((h[0] & 0x70) || !(h[1] & 0x80))
        code = WS_CLOSE_PROTOCOL;
    else if(op != WS_OP_CONT && op != WS_OP_TEXT && op != WS_OP_BINARY &&
            op != WS_OP_CLOSE && op != WS_OP_PING && op != WS_OP_PONG)
        code = WS_CLOSE_PROTOCOL;
    else
        code = 0;
    if(code)
        goto fail;

    if(plen == 126)
    {
        nop_err_if(ws_read(ws, ext, 2));
        plen = ((unsigned long long) ext[0] << 8) | ext[1];
    } else if(plen == 127) {
        nop_err_if(ws_read(ws, ext, 8));
        for(plen = 0, i = 0; i < 8; ++i)
            plen = (plen << 8) | ext[i];
    }
    nop_err_if(ws_read(ws, mask, 4));

    if(op >= WS_OP_CLOSE)
    {   /* control frames: short, whole, between the parts of a message */
        if(!fin || plen > sizeof ctl)
        {
            code = WS_CLOSE_PROTOCOL;
            goto fail;
        }
        nop_err_if(ws_read(ws, ctl, (size_t) plen));
        for(i = 0; i < plen; ++i)
            ctl[i] ^= mask[i % 4];

        if(op == WS_OP_PING)
            nop_err_if(ws_send_frame(ws, WS_OP_PONG, ctl, (size_t) plen));
        else if(op == WS_OP_CLOSE)
        {   /* answer with the client's code (1000 if it gave none) */
            code = plen >= 2 ? ((unsigned char) ctl[0] << 8) |
                (unsigned char) ctl[1] : WS_CLOSE_NORMAL;
            (void) ws_send_close(ws, code == 1005 ? WS_CLOSE_NORMAL : code,
                    NULL);
            ws->ended = 1;
            rc = WS_CLOSED;
        }
        timerm_del(al);
        return rc;
    }

    /* a data frame: a new message, or the next part of the current one */
    if((op == WS_OP_CONT) != (ws->msg_type != 0))
    {
        code = WS_CLOSE_PROTOCOL;
        goto fail;
    }
    if(op != WS_OP_CONT)
    {
        ws->msg_type = op;
        ws->len = 0;
    }
    if(plen > ws->max || ws->len + plen > ws->max)
    {
        code = WS_CLOSE_TOO_BIG;
        goto fail;
    }

    n = (size_t) plen;
    dbg_err_if(ws_grow(ws, n));
    dst = ws->msg + ws->len;
    nop_err_if(ws_read(ws, dst, n));
    for(i = 0; i < n; ++i)
        dst[i] ^= mask[i % 4];
    ws->len += n;
    timerm_del(al);
    al = NULL;

    if(!fin)
        return WS_AGAIN;

    ws->msg[ws->len] = '\0';
    if(ws->msg_type == WS_OP_TEXT &&
            !ws_utf8_ok((unsigned char *) ws->msg, ws->len))
    {
        code = WS_CLOSE_DATA;
        goto fail;
    }

    return 0;

fail:
    if(al)
        timerm_del(al);
    (void) ws_send_close(ws, code, NULL);
    ws->ended = 1;
    return WS_CLOSED;
err:
    if(al)
        timerm_del(al);
    ws->ended = 1;
    return WS_CLOSED;
}

/**
 * \brief   Receive a message
 *
 * Read the frames that have arrived; pings are answered, a close is
 * answered and ends the connection.
 *
 * \param ws     the connection
 * \param type   ::WS_TEXT (valid UTF-8) or ::WS_BINARY
 * \param pdata  the message, NUL-terminated, valid until the next call
 * \param plen   its length
 *
 * \return \c 0 with a message, ::WS_AGAIN if no whole message has come
 *         yet (wait again), ::WS_CLOSED when the connection has ended
 */
int ws_recv(ws_t *ws, int *type, const char **pdata, size_t *plen)
{
    int rc;

    dbg_return_if (ws == NULL || type == NULL || pdata == NULL ||
            plen == NULL, WS_CLOSED);

    if(ws->ended)
        return WS_CLOSED;

    do {
        if((rc = ws_read_frame(ws)) == 0)
        {
            *type = ws->msg_type == WS_OP_TEXT ? WS_TEXT : WS_BINARY;
            *pdata = ws->msg;
            *plen = ws->len;
            ws->msg_type = 0;
            return 0;
        }
    } while(rc == WS_AGAIN && ws_buffered(ws));

    return rc;
}

/**
 * \brief   Send a message (::WS_TEXT, which must be UTF-8, or ::WS_BINARY)
 *
 * \return \c 0, or \c ~0 if the connection is gone
 */
int ws_send(ws_t *ws, int type, const char *data, size_t len)
{
    dbg_return_if (ws == NULL || (data == NULL && len), ~0);
    dbg_return_if (type != WS_TEXT && type != WS_BINARY, ~0);

    if(ws->close_sent || ws->ended)
        return ~0;

    return ws_send_frame(ws, type == WS_TEXT ? WS_OP_TEXT : WS_OP_BINARY,
            data, len);
}

/**
 * \brief   Send a ping (the client answers with a pong, which ws_recv()
 *          takes): keeps idle connections open through proxies
 */
int ws_ping(ws_t *ws)
{
    dbg_return_if (ws == NULL, ~0);

    return (ws->close_sent || ws->ended) ? ~0 :
        ws_send_frame(ws, WS_OP_PING, "", 0);
}

/**
 * \brief   Close the connection: send a close frame with \p code (1000 for
 *          a normal end) and wait briefly for the client's
 */
int ws_close(ws_t *ws, int code, const char *reason)
{
    const char *data;
    size_t len;
    long long end;
    int type, rc;

    dbg_return_if (ws == NULL, ~0);

    if(ws->close_sent || ws->ended)
        return 0;

    dbg_err_if(ws_send_close(ws, code, reason));

    /* wait for the client's close frame (data still in flight is dropped) */
    for(end = ws_now_ms() + WS_CLOSE_WAIT; ws_now_ms() < end; )
    {
        if(ws_wait(ws, -1, (int) (end - ws_now_ms())) != WS_MESSAGE)
            break;
        if((rc = ws_recv(ws, &type, &data, &len)) == WS_CLOSED)
            break;
    }
    ws->ended = 1;

    return 0;
err:
    return ~0;
}

/**
 * \brief   The subprotocol chosen in ws_accept() ("" if none)
 */
const char *ws_protocol(ws_t *ws)
{
    return ws ? ws->protocol : "";
}

/**
 * \brief   Set the largest message ws_recv() accepts (1 MB by default); a
 *          larger one closes the connection with 1009
 */
int ws_set_max_message(ws_t *ws, size_t max)
{
    dbg_return_if (ws == NULL || max == 0, ~0);

    ws->max = max;

    return 0;
}

/**
 * \brief   Free the connection object (the connection itself is closed
 *          when the page ends)
 */
void ws_free(ws_t *ws)
{
    if(ws == NULL)
        return;

    U_FREE(ws->msg);
    u_free(ws);
}
