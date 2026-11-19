/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_HOOK_H_
#define _KLIN_HOOK_H_
#include <klin/request.h>
#include <klin/response.h>
#include <klin/session.h>

struct hook_s;
typedef struct hook_s hook_t;

#ifdef __cplusplus
extern "C" {
#endif 

#ifndef ENABLE_HOOKS
    #include <ctype.h>
    #define hook_create(hook) isspace(0)  /* nop */
    #define hook_free(hook) isspace(0)    /* nop */
#else

/* server init/term hooks */
typedef int (*hook_server_init_t)(void);
typedef int (*hook_server_term_t)(void);

int hook_server_init( hook_server_init_t );
int hook_server_term( hook_server_term_t );

/* children init/term hooks */
typedef int (*hook_child_init_t)(void);
typedef int (*hook_child_term_t)(void);

int hook_child_init( hook_child_init_t );
int hook_child_term( hook_child_term_t );

/* per-request hook */
typedef int (*hook_request_t)(request_t *, response_t *);
int hook_request( hook_request_t );

/* server loop hook */
typedef int (*hook_server_loop_t)(void);
int hook_server_loop( hook_server_loop_t );

/* hooks container object */
int hook_create( hook_t **phook);
int hook_free( hook_t *hook);

/* user-provided function used to register hooks */
void hooks_setup(void);

#endif  /* ENABLE_HOOKS */

#ifdef __cplusplus
}
#endif 

#endif
