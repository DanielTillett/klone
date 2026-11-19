/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_VAR_PRV_H_
#define _KLIN_VAR_PRV_H_

#include <u/libu.h>

#ifdef __cplusplus
extern "C" {
#endif

struct var_s
{
    TAILQ_ENTRY(var_s) np;  /* next & prev pointers   */
    u_string_t *sname;      /* var string name        */
    u_string_t *svalue;     /* var string value       */
    char *data;
    size_t size;
    void *opaque;
};

#ifdef __cplusplus
}
#endif 

#endif
