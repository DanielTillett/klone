/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_TIMERM_H_
#define _KLIN_TIMERM_H_

#ifdef __cplusplus
extern "C" {
#endif

struct timerm_s;
typedef struct timerm_s timerm_t;

struct talarm_s;
typedef struct talarm_s talarm_t;

typedef int (*talarm_cb_t)(talarm_t *, void *arg);

int timerm_add(int secs, talarm_cb_t cb, void *arg, talarm_t **pa);
int timerm_del(talarm_t *a);
int timerm_reschedule(talarm_t *a, int secs, talarm_cb_t cb, void *arg);

#ifdef __cplusplus
}
#endif 

#endif
