/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_SUPPLIER_H_
#define _KLIN_SUPPLIER_H_

#include <klin/http.h>
#include <klin/request.h>
#include <klin/response.h>
#include <klin/page.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct supplier_s
{
    const char *name;       /* descriptive name          */
    int (*init)(void);
    void (*term)(void);
    int (*is_valid_uri)(http_t *h, request_t *rq, const char *file, size_t len,
            void **handle, time_t *mtime);
    int (*serve)(request_t *, response_t*);
} supplier_t;

#ifdef __cplusplus
}
#endif 

#endif
