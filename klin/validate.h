/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_VALIDATE_H_
#define _KLIN_VALIDATE_H_

#include <klin/http.h>
#include <klin/request.h>
#include <klin/vhost.h>

#ifdef __cplusplus
extern "C" {
#endif

/* declarative request validation of a vhost (doc/VALIDATE), used by the
 * HTTP server */
struct validator_s;
typedef struct validator_s validator_t;

int validate_load(vhost_t *vhost);
void validate_free(vhost_t *vhost);
int validate_request(http_t *h, request_t *rq, const char *path);

#ifdef __cplusplus
}
#endif

#endif
