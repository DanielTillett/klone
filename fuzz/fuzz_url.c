/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* URL decoding and the other escapes (hex, HTML, SQL), and the URI path
 * normalisation that keeps a request inside the document root: a
 * normalised path never climbs out of it. */

#include "fuzz.h"
#include <klin/utils.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *input, *output, *path;
    size_t cap = 6 * size + 1;

    if(size > FUZZ_MAX)
        return 0;
    input = fuzz_string(data, size);
    if((output = malloc(cap)) == NULL)
        abort();

    (void) u_urlncpy_s(output, cap, input, size, URLCPY_DECODE);
    (void) u_urlncpy_s(output, cap, input, size, URLCPY_ENCODE);
    (void) u_hexncpy_s(output, cap, input, size, HEXCPY_DECODE);
    (void) u_htmlncpy_s(output, cap, input, size, HTMLCPY_DECODE);
    (void) u_htmlncpy_s(output, cap, input, size, HTMLCPY_ENCODE);
    (void) u_sqlncpy_s(output, cap, input, size, SQLCPY_ENCODE);

    /* decode, then normalise as the request does */
    path = fuzz_string(data, size);
    if(u_urlncpy_s(output, cap, input, size, URLCPY_DECODE) > 0 &&
            output[0] == '/')
    {
        (void) u_strlcpy(path, output, size + 1);
        if(u_uri_normalize(path) == 0 &&
                (path[0] != '/' || strstr(path, "/../") ||
                 (strlen(path) >= 3 && !strcmp(path + strlen(path) - 3, "/.."))))
            abort();    /* a path out of the root */
    }

    free(path);
    free(output);
    free(input);
    return 0;
}
