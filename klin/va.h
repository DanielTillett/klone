/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_VA_H_
#define _KLIN_VA_H_

#include "klin_conf.h"
#include <u/libu.h>
#include <stdarg.h>

/* provide some suitable method for performing C99 va_copy */
#if defined(va_copy)
    /* C99 va_copy */
    #define kl_va_copy(a, b)  va_copy(a, b)
#elif defined(__va_copy)
    /* GNU libc va_copy replacement */
    #define kl_va_copy(a, b)  __va_copy(a, b)
#else
    #define VA_COPY_UNAVAIL 1
#endif

#endif  /* !_KLIN_VA_H_ */
