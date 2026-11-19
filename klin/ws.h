/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_WS_H_
#define _KLIN_WS_H_

#include <stddef.h>
#include <klin/request.h>
#include <klin/response.h>

#ifdef __cplusplus
extern "C" {
#endif

/* WebSockets (RFC 6455) from a page, see doc/WEBSOCKET:
 *
 *     ws_t *ws;
 *     if(ws_accept(request, response, NULL, 0, &ws) == 0)
 *     {
 *         while(ws_wait(ws, -1, 30000) != WS_CLOSED)
 *             if(ws_recv(ws, &type, &data, &len) == 0)
 *                 ws_send(ws, type, data, len);           (an echo)
 *         ws_free(ws);
 *     }
 */

struct ws_s;
typedef struct ws_s ws_t;

/* message types */
enum { WS_TEXT = 1, WS_BINARY = 2 };

/* ws_accept() flags */
enum { WS_ANY_ORIGIN = 1 };   /* accept a page of another site (see doc) */

/* what ws_wait() and ws_recv() return */
enum {
    WS_MESSAGE = 1,         /* data to read: call ws_recv()               */
    WS_READY = 2,           /* the descriptor given is readable           */
    WS_TIMEOUT = 3,         /* the time given has passed                  */
    WS_CLOSED = 4,          /* the connection is closed (or failed)       */
    WS_AGAIN = 5            /* ws_recv(): only control frames came        */
};

int ws_accept(request_t *rq, response_t *rs, const char *protocols, int flags,
        ws_t **pws);
int ws_wait(ws_t *ws, int fd, int ms);
int ws_recv(ws_t *ws, int *type, const char **pdata, size_t *plen);
int ws_send(ws_t *ws, int type, const char *data, size_t len);
int ws_ping(ws_t *ws);
int ws_close(ws_t *ws, int code, const char *reason);
const char *ws_protocol(ws_t *ws);
int ws_set_max_message(ws_t *ws, size_t max);
void ws_free(ws_t *ws);

#ifdef __cplusplus
}
#endif

#endif
