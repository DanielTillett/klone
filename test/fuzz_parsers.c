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
    free(output);
    free(input);
    return 0;
}
