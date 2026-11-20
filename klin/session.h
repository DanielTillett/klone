/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_SESSION_H_
#define _KLIN_SESSION_H_

#include <u/libu.h>
#include <klin/request.h>
#include <klin/response.h>
#include <klin/vars.h>

#ifdef __cplusplus
extern "C" {
#endif

struct session_s;
typedef struct session_s session_t;

int session_free(session_t*);
int session_remove(session_t*);
int session_clean(session_t*);
int session_age(session_t*);

vars_t *session_get_vars(session_t*);
const char *session_get(session_t*, const char*);
const char *session_get_id (session_t *ss);
int session_set(session_t*, const char*, const char*);
int session_del(session_t*, const char*);
int session_load(session_t *ss);
int session_save(session_t *ss);
int session_save_to_io(session_t*, const char*);

/* a new session id, keeping the data (call it at login and at any change
   of privilege, before the page prints anything): doc/SESSIONS */
int session_regenerate_id(session_t *ss);

/* CSRF: the session's token for forms and requests, and the check of a
   request's token (X-CSRF-Token field or csrf_token argument; GET and HEAD
   need none): 0 if it may go ahead */
const char *session_csrf_token(session_t *ss);
int session_csrf_check(session_t *ss, request_t *rq);

#ifdef SSL_ON
int session_set_cipher_key(session_t*, const char*, size_t);
int session_get_cipher_key(session_t*, char*, size_t*);
#endif

#ifdef __cplusplus
}
#endif 

#endif
