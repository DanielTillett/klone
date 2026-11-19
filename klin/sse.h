/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_SSE_H_
#define _KLIN_SSE_H_

#include <klin/request.h>
#include <klin/response.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Server-Sent Events (the HTML "text/event-stream" format) from a page:
 *
 *     sse_start(request, response);
 *     while(sse_wait(request, my_fd, 15000) != SSE_CLOSED)
 *         if(sse_send(response, "tick", NULL, "data"))
 *             break;
 *
 * Each event is sent at once (chunked on HTTP/1.1). See doc/SSE. */

/* what sse_wait() returns */
enum {
    SSE_READY = 1,          /* the descriptor given is readable          */
    SSE_TIMEOUT = 2,        /* the time given has passed                 */
    SSE_CLOSED = 3          /* the client went away                      */
};

int sse_start(request_t *rq, response_t *rs);
int sse_send(response_t *rs, const char *event, const char *id,
        const char *data);
int sse_comment(response_t *rs, const char *text);
int sse_retry(response_t *rs, unsigned int ms);
int sse_wait(request_t *rq, int fd, int ms);
const char *sse_last_event_id(request_t *rq);

#ifdef __cplusplus
}
#endif

#endif
