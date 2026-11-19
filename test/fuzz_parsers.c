/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */
/* Link against the real libraries, not the isolated regression test doubles. */
#include "klin_conf.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <u/libu.h>
#include <klin/header.h>
#include <klin/utils.h>

int facility = LOG_LOCAL0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    io_t *io = NULL;
    header_t *header = NULL;
    char *input, *output;
    if (size > 65536)
        return 0;
    input = malloc(size + 1);
    output = malloc(6 * size + 1);
    if (!input || !output)
        abort();
    memcpy(input, data, size);
    input[size] = '\0';
    if (io_mem_create(input, size, 0, &io) == 0 && header_create(&header) == 0)
        (void)header_load(header, io);
    if (header)
        header_free(header);
    if (io)
        io_free(io);
    (void)u_urlncpy_s(output, 6 * size + 1, input, size, URLCPY_DECODE);
    (void)u_hexncpy_s(output, 6 * size + 1, input, size, HEXCPY_DECODE);
    (void)u_htmlncpy_s(output, 6 * size + 1, input, size, HTMLCPY_DECODE);
    (void)u_sqlncpy_s(output, 6 * size + 1, input, size, SQLCPY_ENCODE);
    free(output);
    free(input);
    return 0;
}
