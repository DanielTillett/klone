/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */
/* Link against the real libraries, not the isolated regression test doubles. */
#include "klin_conf.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <u/libu.h>
#include <klin/header.h>
#include <klin/translat.h>
#include <klin/utils.h>
#include <klin/json.h>

int facility = LOG_LOCAL0;

/* the page translator: the same bytes as a .kl1 page (parser and C code
   generator), the generated C going to /dev/null */
static void fuzz_translate(char *input, size_t size)
{
    static trans_info_t ti;
    io_t *in = NULL, *out = NULL;
    int fd;

    memset(&ti, 0, sizeof ti);
    (void) u_strlcpy(ti.uri, "/fuzz.kl1", sizeof ti.uri);
    (void) u_strlcpy(ti.file_in, "fuzz.kl1", sizeof ti.file_in);

    if ((fd = open("/dev/null", O_WRONLY)) < 0)
        abort();
    if (io_mem_create(input, size, 0, &in) == 0 &&
            io_fd_create(fd, IO_FD_CLOSE, &out) == 0)
        (void)translate_script_to_c(in, out, &ti);
    else
        close(fd);
    if (in)
        io_free(in);
    if (out)
        io_free(out);
}

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
        n = strlen(buf);
    }
    if (w)
        json_writer_free(w);
    if (io)
        io_free(io);
    return n;
}

/* the JSON reader on any input; a document it accepts must write out and
   read back to the same text (parse, write, parse, write is stable) */
static void fuzz_json(const char *input, size_t size)
{
    json_t *a = NULL, *b = NULL;
    size_t cap = 8 * size + 64, n1, n2;
    char *first, *second;

    if (json_parse(input, size, &a, NULL, 0))
        return;
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
}

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
    fuzz_translate(input, size);
    fuzz_json(input, size);
    free(output);
    free(input);
    return 0;
}
