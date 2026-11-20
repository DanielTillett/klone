/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* The page translator: the input as a .kl1 page (parser and C code
 * generator), the generated C going to /dev/null. */

#include "fuzz.h"
#include <fcntl.h>
#include <unistd.h>
#include <klin/io.h>
#include <klin/translat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static trans_info_t ti;
    io_t *in = NULL, *out = NULL;
    char *input;
    int fd;

    if (size > FUZZ_MAX)
        return 0;
    input = fuzz_string(data, size);
    memset(&ti, 0, sizeof ti);
    (void) u_strlcpy(ti.uri, "/fuzz.kl1", sizeof ti.uri);
    (void) u_strlcpy(ti.file_in, "fuzz.kl1", sizeof ti.file_in);

    if ((fd = open("/dev/null", O_WRONLY)) < 0)
        abort();
    if (io_mem_create(input, size, 0, &in) == 0 &&
            io_fd_create(fd, IO_FD_CLOSE, &out) == 0)
        (void) translate_script_to_c(in, out, &ti);
    else
        close(fd);
    if (in)
        io_free(in);
    if (out)
        io_free(out);
    free(input);
    return 0;
}
