/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define SZ  64

int va_func (const char *fmt, ...)
{
    va_list ap;
    char b1[SZ], b2[SZ];

    va_start(ap, fmt);
    (void) vsnprintf(b1, SZ, fmt, ap);
    (void) vsnprintf(b2, SZ, fmt, ap);
    va_end(ap);

    return strcmp(b1, b2) == 0 ? 0 : 1;
}

int main (void)
{
    return va_func("%s %d %c", "string", 100, 'x');
}
