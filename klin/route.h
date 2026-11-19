/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_ROUTE_H_
#define _KLIN_ROUTE_H_

#include <klin/http.h>
#include <klin/request.h>
#include <klin/response.h>
#include <klin/vhost.h>

#ifdef __cplusplus
extern "C" {
#endif

/* REST-style routes of a vhost (doc/ROUTES), used by the HTTP server */
int route_load(vhost_t *vhost);
int route_dispatch(http_t *h, request_t *rq, int *routed);
int route_allow(http_t *h, request_t *rq, response_t *rs);

#ifdef __cplusplus
}
#endif

#endif
