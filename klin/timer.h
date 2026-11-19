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

/* what timerm_wait() waits for */
enum { TIMERM_WAIT_READ = 1, TIMERM_WAIT_WRITE = 2 };

/* An alarm runs when it is due and the process waits in timerm_wait() (the
 * io drivers do, for reads and writes) or calls timerm_run(); never from a
 * signal handler. A fired alarm is off the list but still allocated:
 * timerm_del() it, or timerm_reschedule() it */
int timerm_add(int secs, talarm_cb_t cb, void *arg, talarm_t **pa);
int timerm_del(talarm_t *a);
int timerm_reschedule(talarm_t *a, int secs, talarm_cb_t cb, void *arg);
int timerm_run(void);
int timerm_armed(void);
int timerm_wait(int *pfd, int events);

#ifdef __cplusplus
}
#endif 

#endif
