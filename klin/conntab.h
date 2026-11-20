/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_CONNTAB_H_
#define _KLIN_CONNTAB_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Connections being served, shared by every worker of klind, for the caps
 * on connections per client address and on long-lived (SSE, WebSocket)
 * responses (doc/LIMITS). A worker serves one connection at a time and
 * holds one slot meanwhile. */
enum { CONNTAB_SLOTS = 1024, CONNTAB_CLASSES = 64 };

/* a class of connections (an HTTP server) with its caps (0: no cap); called
 * before the workers fork. Returns the class, or -1 if there is none left */
int conntab_class(int per_peer, int streams);

/* this process starts serving a connection from 'peer' (text address):
 * ~0 if the class already has per_peer connections from it */
int conntab_enter(int cls, const char *peer);

/* the connection now carries a long-lived response: ~0 if the class
 * already has 'streams' of them */
int conntab_stream(void);

/* the connection is over */
void conntab_leave(void);

/* free the slot of a worker that died without leaving (the parent) */
void conntab_reap(pid_t pid);

#ifdef __cplusplus
}
#endif

#endif
