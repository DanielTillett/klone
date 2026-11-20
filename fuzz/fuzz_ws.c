/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* WebSocket frames from a client, after the handshake: the input is what
 * the client sends (frames, fragments, control frames, close), read with
 * ws_recv() until the connection ends. The server's replies (pong, close)
 * go back over the socket and are dropped. */

#include "fuzz.h"
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include "src/libpage/ws.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int sv[2], type, rc, i;
    const char *msg;
    size_t len;
    ws_t ws;
    io_t *io = NULL;

    if(size > FUZZ_MAX)
        return 0;
    signal(SIGPIPE, SIG_IGN);
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
        abort();
    /* a socket pair holds more than FUZZ_MAX bytes: this never blocks */
    {
        int big = 4 * FUZZ_MAX;
        (void) setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
        (void) setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    }
    if(size && write(sv[0], data, size) != (ssize_t) size)
        abort();
    close(sv[0]);   /* end of input; replies get EPIPE */

    if(io_fd_create(sv[1], IO_FD_CLOSE, &io))
        abort();
    memset(&ws, 0, sizeof ws);
    ws.io = io;
    ws.max = 16384;

    for(i = 0; i < 1000; ++i)
    {
        rc = ws_recv(&ws, &type, &msg, &len);
        if(rc == WS_CLOSED || rc < 0)
            break;
        if(rc == 0 && type == WS_TEXT && msg[len] != '\0')
            abort();    /* a text message is NUL-terminated */
    }

    U_FREE(ws.msg);
    io_free(io);
    return 0;
}
