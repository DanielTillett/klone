/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* A request as a client sends it: request line, header (limits, smuggling
 * checks, Content-Length, cookies, If-Modified-Since) and, when the header
 * parses, the query string and a urlencoded or multipart body. */

#include "fuzz.h"
#include "src/libpage/request.c"

/* a request with the default limits, without a server (request_create()
   needs one for its configuration) */
static request_t *fuzz_request(io_t *io)
{
    request_t *rq = u_malloc(sizeof(request_t));

    if(rq == NULL)
        abort();
    memset(rq, 0, sizeof *rq);
    if(header_create(&rq->header))
        abort();
    rq->idle_timeout = REQUEST_DEFAULT_IDLE_TIMEOUT;
    rq->post_timeout = REQUEST_DEFAULT_POST_TIMEOUT;
    rq->post_maxsize = FUZZ_MAX;
    rq->max_fields = REQUEST_DEFAULT_MAX_FIELDS;
    rq->max_line = REQUEST_DEFAULT_MAX_LINE;
    rq->max_header = REQUEST_DEFAULT_MAX_HEADER;
    rq->temp_dir = "/tmp";
    (void) request_bind(rq, io);
    return rq;
}

/* parse 'text' as a whole request */
static void fuzz_parse(char *text, size_t size)
{
    request_t *rq;
    io_t *io = NULL;

    if(io_mem_create(text, size, 0, &io))
        abort();
    rq = fuzz_request(io);
    if(request_parse_header(rq, NULL, NULL) == 0)
    {
        (void) request_parse_data(rq);
        (void) request_get_args(rq);
        (void) request_get_cookies(rq);
    }
    (void) request_free(rq);    /* frees the io it is bound to */
}

#ifndef FUZZ_REQUEST_NO_MAIN
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *text;

    if(size > FUZZ_MAX)
        return 0;
    text = fuzz_string(data, size);
    fuzz_parse(text, size);
    free(text);
    return 0;
}
#endif
