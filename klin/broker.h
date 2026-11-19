/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_BROKER_H_
#define _KLIN_BROKER_H_

#include <klin/http.h>
#include <klin/request.h>
#include <klin/response.h>
#include <klin/page.h>

#ifdef __cplusplus
extern "C" {
#endif 

struct broker_s;
typedef struct broker_s broker_t;

int broker_create(broker_t **pb);
int broker_free(broker_t* b);
int broker_is_valid_uri(broker_t *b, http_t *h, request_t *rq, const char *buf,
        size_t len);
int broker_serve(broker_t *b, http_t *h, request_t *rq, response_t *rs);

#ifdef __cplusplus
}
#endif 

#endif
