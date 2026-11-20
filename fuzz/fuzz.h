/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* Shared by the fuzz targets (doc/FUZZING). Each target is a libFuzzer
 * entry point over the real code; some include the .c file of the parser
 * they test, to reach its static functions. */

#ifndef _KLIN_FUZZ_H_
#define _KLIN_FUZZ_H_

#include "klin_conf.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <u/libu.h>

/* LibU's log facility */
int facility = LOG_LOCAL0;

/* inputs over this are skipped: no parser needs more to reach its limits */
enum { FUZZ_MAX = 65536 };

/* a NUL-terminated copy of the input */
static char *fuzz_string(const uint8_t *data, size_t size)
{
    char *s = malloc(size + 1);

    if(s == NULL)
        abort();
    memcpy(s, data, size);
    s[size] = '\0';
    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif
