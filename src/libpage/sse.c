/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* Server-Sent Events (doc/SSE). The page holds the connection, and its
 * worker, for as long as it streams: sse_wait() is where it waits, with
 * poll(2) on the client socket (to see it go away), an optional descriptor
 * of the page's own (to wake up when there is something to send) and the
 * timer's alarms. A write that the client does not take in
 * SSE_WRITE_TIMEOUT seconds closes the connection. */

#include "klin_conf.h"
#include <errno.h>
#include <string.h>
#include <time.h>
#ifndef OS_WIN
#include <poll.h>
#endif
#include <u/libu.h>
#include <klin/io.h>
#include <klin/sse.h>
#include <klin/http.h>
#include <klin/conntab.h>
#include <klin/timer.h>

enum { SSE_WRITE_TIMEOUT = 30 };

static int sse_cb_write_timeout(talarm_t *al, void *arg)
{
    u_unused_args(al);

    warn("SSE client stopped reading, connection closed");
    io_close((io_t *) arg);

    return 0;
}

/* write and send 'len' bytes at once, within SSE_WRITE_TIMEOUT */
static int sse_write(response_t *rs, const char *buf, size_t len)
{
    io_t *out = response_io(rs);
    talarm_t *al = NULL;

    dbg_err_if(timerm_add(SSE_WRITE_TIMEOUT, sse_cb_write_timeout, out, &al));
    nop_err_if(io_write(out, buf, len) < (ssize_t) len);
    nop_err_if(io_flush(out));
    timerm_del(al);

    return 0;
err:
    if(al)
        timerm_del(al);
    return ~0;
}

/* an event field value cannot hold a line break */
static int sse_one_line(const char *s)
{
    return s == NULL || strpbrk(s, "\r\n") == NULL;
}

/**
 * \brief   Start an event stream
 *
 * Send the response header (Content-Type: text/event-stream, no caching)
 * at once; from here everything the page prints goes to the client as it
 * is written. Call it before printing anything else.
 *
 * \return \c 0, or \c ~0 if the client is gone
 */
int sse_start(request_t *rq, response_t *rs)
{
    static const char hello[] = ": klin\n\n";

    dbg_return_if (rq == NULL || rs == NULL, ~0);

    /* max_streams of them are open: try again later */
    if(conntab_stream())
    {
        (void) response_set_status(rs, HTTP_STATUS_SERVICE_UNAVAILABLE);
        (void) response_set_field(rs, "Retry-After", "5");
        return ~0;
    }

    dbg_err_if(response_set_content_type(rs, "text/event-stream"));
    dbg_err_if(response_set_field(rs, "Cache-Control", "no-store"));
    /* proxies that buffer responses (nginx) pass this one on at once */
    dbg_err_if(response_set_field(rs, "X-Accel-Buffering", "no"));
    dbg_err_if(response_set_streaming(rs));

    /* a comment, so the header goes out now */
    return sse_write(rs, hello, sizeof hello - 1);
err:
    return ~0;
}

/**
 * \brief   Send an event
 *
 * \param rs     the response of an sse_start() page
 * \param event  event type (NULL: "message"); one line
 * \param id     event id, what the browser sends back in Last-Event-ID
 *               when it reconnects (NULL: none); one line
 * \param data   event data; a multi-line value is sent as several "data"
 *               lines and received with the line breaks
 *
 * \return \c 0, or \c ~0 if the client is gone (stop streaming)
 */
int sse_send(response_t *rs, const char *event, const char *id,
        const char *data)
{
    u_string_t *ev = NULL;
    const char *p, *e;
    int rc;

    dbg_return_if (rs == NULL || data == NULL, ~0);
    dbg_return_if (!sse_one_line(event) || !sse_one_line(id), ~0);

    dbg_err_if(u_string_create(NULL, 0, &ev));

    if(event)
        dbg_err_if(u_string_aprintf(ev, "event: %s\n", event));
    if(id)
        dbg_err_if(u_string_aprintf(ev, "id: %s\n", id));

    /* one "data:" line per line of data (CRLF, CR or LF) */
    for(p = data;; p = e + ((e[0] == '\r' && e[1] == '\n') ? 2 : 1))
    {
        e = p + strcspn(p, "\r\n");
        dbg_err_if(u_string_aprintf(ev, "data: %.*s\n", (int) (e - p), p));
        if(*e == '\0')
            break;
    }
    dbg_err_if(u_string_aprintf(ev, "\n"));

    rc = sse_write(rs, u_string_c(ev), u_string_len(ev));
    u_string_free(ev);

    return rc;
err:
    if(ev)
        u_string_free(ev);
    return ~0;
}

/**
 * \brief   Send a comment line (": text"), e.g. to keep an idle stream
 *          open through proxies that close silent connections
 */
int sse_comment(response_t *rs, const char *text)
{
    char buf[512];

    dbg_return_if (rs == NULL || !sse_one_line(text), ~0);
    dbg_return_if (u_snprintf(buf, sizeof buf, ": %s\n\n", text ? text : ""),
            ~0);

    return sse_write(rs, buf, strlen(buf));
}

/**
 * \brief   Tell the browser how long to wait before reconnecting (ms)
 */
int sse_retry(response_t *rs, unsigned int ms)
{
    char buf[64];

    dbg_return_if (rs == NULL, ~0);
    dbg_return_if (u_snprintf(buf, sizeof buf, "retry: %u\n\n", ms), ~0);

    return sse_write(rs, buf, strlen(buf));
}

/**
 * \brief   The id of the last event the browser got, when it reconnects
 *
 * \return the Last-Event-ID header value, or \c NULL
 */
const char *sse_last_event_id(request_t *rq)
{
    return request_get_field_value(rq, "Last-Event-ID");
}

static long long sse_now_ms(void)
{
    struct timespec ts;

    (void) clock_gettime(CLOCK_MONOTONIC, &ts);

    return (long long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/**
 * \brief   Wait for something to send, or for the client to go away
 *
 * Wait until \p fd (a pipe or socket of the page's own; \c -1 for none) is
 * readable, \p ms milliseconds have passed (\c -1: no limit), or the client
 * closes the connection. Alarms (timer.h) run while waiting.
 *
 * \return ::SSE_READY, ::SSE_TIMEOUT or ::SSE_CLOSED (also when the
 *         connection fails)
 */
int sse_wait(request_t *rq, int fd, int ms)
{
#ifdef OS_WIN
    u_unused_args(rq, fd, ms);
    return SSE_CLOSED;
#else
    struct pollfd p[2];
    long long end = ms < 0 ? -1 : sse_now_ms() + ms, left;
    int n, rc, t, cfd;

    dbg_return_if (rq == NULL, SSE_CLOSED);

    for(;;)
    {
        t = timerm_run();

        /* the client socket: an SSE client sends nothing, so anything
           readable is a close (or a reset) */
        if((cfd = io_get_fd(request_io(rq))) < 0)
            return SSE_CLOSED;
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
            if((left = end - sse_now_ms()) <= 0)
                return SSE_TIMEOUT;
            if(t < 0 || left < t)
                t = (int) U_MIN(left, 0x7fffffff);
        }

        rc = poll(p, (nfds_t) n, t);
        if(rc < 0 && errno == EINTR)
            continue;
        if(rc < 0)
            return SSE_CLOSED;

        if(p[0].revents)
            return SSE_CLOSED;
        if(n == 2 && p[1].revents)
            return SSE_READY;
    }
#endif
}
