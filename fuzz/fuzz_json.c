/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* The JSON reader and writer: whatever parses is written out, the output
 * must parse, and writing that again must give the same bytes. */

#include "fuzz.h"
#include <klin/io.h>
#include <klin/json.h>

/* write a parsed document to 'buf' (its length, 0 if the writer failed) */
static size_t fuzz_json_write(const json_t *j, char *buf, size_t size)
{
    json_writer_t *w = NULL;
    io_t *io = NULL;
    size_t n = 0;

    memset(buf, 0, size);
    if (io_mem_create(buf, size - 1, 0, &io) == 0 &&
            json_writer_create(io, &w) == 0 && json_value(w, j) == 0 &&
            json_writer_free(w) == 0)
    {
        w = NULL;
        io_flush(io);
        n = strlen(buf);    /* the writer escapes NUL: no NUL in its output */
    }
    if (w)
        json_writer_free(w);
    if (io)
        io_free(io);
    return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    json_t *a = NULL, *b = NULL;
    size_t cap = 8 * size + 64, n1, n2;
    char *input, *first, *second;

    if (size > FUZZ_MAX)
        return 0;
    input = fuzz_string(data, size);
    if (json_parse(input, size, &a, NULL, 0))
    {
        free(input);
        return 0;
    }
    first = malloc(cap);
    second = malloc(cap);
    if (!first || !second)
        abort();
    n1 = fuzz_json_write(a, first, cap);
    if (n1 == 0 || json_parse(first, n1, &b, NULL, 0))
        abort();    /* the writer's output must be valid JSON */
    n2 = fuzz_json_write(b, second, cap);
    if (n1 != n2 || memcmp(first, second, n1))
        abort();
    json_free(a);
    json_free(b);
    free(first);
    free(second);
    free(input);
    return 0;
}
