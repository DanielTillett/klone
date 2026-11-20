/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* A multipart/form-data body (boundary "XyZ"): the input is the body of a
 * POST whose header is fixed, so the fuzzer spends its time in the parts,
 * their headers and the uploads written to temporary files. */

#define FUZZ_REQUEST_NO_MAIN
#include "fuzz_request.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char head[160], *text;
    int n;

    if(size > FUZZ_MAX)
        return 0;
    n = snprintf(head, sizeof head, "POST /up?a=1 HTTP/1.1\r\nHost: x\r\n"
            "Content-Type: multipart/form-data; boundary=XyZ\r\n"
            "Content-Length: %zu\r\n\r\n", size);
    if((text = malloc((size_t) n + size + 1)) == NULL)
        abort();
    memcpy(text, head, (size_t) n);
    memcpy(text + n, data, size);
    text[(size_t) n + size] = '\0';
    fuzz_parse(text, (size_t) n + size);
    free(text);
    return 0;
}
