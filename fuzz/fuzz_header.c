/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* Header fields alone: the request reader (limits and strict syntax) and
 * the lenient reader used for multipart parts and CGI output. */

#include "fuzz.h"
#include <klin/io.h>
#include <klin/header.h>

static void fuzz_load(char *input, size_t size, int strict)
{
    header_t *header = NULL;
    io_t *io = NULL;
    int status;

    if(io_mem_create(input, size, 0, &io) || header_create(&header))
        abort();
    if(strict)
        (void) header_load_request(header, io, 100, 8192, 32768, &status);
    else
        (void) header_load(header, io);
    header_free(header);
    io_free(io);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *input;

    if(size > FUZZ_MAX)
        return 0;
    input = fuzz_string(data, size);
    fuzz_load(input, size, 1);
    fuzz_load(input, size, 0);
    free(input);
    return 0;
}
