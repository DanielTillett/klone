/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_RUN_H_
#define _KLIN_RUN_H_

#include <klin/request.h>
#include <klin/response.h>

#ifdef __cplusplus
extern "C" {
#endif

/* run a dynamic object page */
int run_page(const char *, request_t*, response_t*);

#ifdef __cplusplus
}
#endif 

#endif
