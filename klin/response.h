/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_RESPONSE_H_
#define _KLIN_RESPONSE_H_

#include <klin/io.h>
#include <klin/header.h>
#include <klin/http.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \file */

enum { COOKIE_MAX_SIZE = 4096 };

struct response_s;
typedef struct response_s response_t;

int response_create(http_t *http, response_t **prs);
int response_free(response_t *rs);
int response_bind(response_t *rs, io_t *);

int response_redirect(response_t *rs, const char *url);

int response_set_status(response_t *rs, int code);
int response_get_status(response_t *rs);
void response_set_method(response_t *rs, int method);
int response_get_method(response_t *rs);

int response_enable_caching(response_t *rs);
int response_disable_caching(response_t *rs);

void response_set_cgi(response_t *rs, int cgi);

int response_print_header(response_t *rs);
int response_print_header_to_io(response_t *rs, io_t *io);
int response_format_header(response_t *rs, size_t extra, char **pbuf,
        size_t *plen);
int response_format_header_reuse(response_t *rs, size_t extra, char **pbuf,
        size_t *pcap, size_t *plen);
size_t response_get_max_header_size(response_t *rs);

/* connection persistence (HTTP keep-alive) */
void response_set_keep_alive(response_t *rs, int keep_alive, int http11);
int response_get_keep_alive(response_t *rs);
int response_set_body_framing(response_t *rs, ssize_t len, int can_chunk);
int response_header_sent(response_t *rs);
int response_is_chunked(response_t *rs);
int response_set_streaming(response_t *rs);
void response_set_header_sent(response_t *rs);
int response_is_streaming(response_t *rs);
int response_has_body(response_t *rs);
void response_close_connection(response_t *rs);

io_t* response_io(response_t *rs);

header_t* response_get_header(response_t *rs);

field_t* response_get_field(response_t *rs, const char *name);
const char* response_get_field_value(response_t *rs, const char *name);

int response_set_field(response_t *rs, const char *name, const char *value);
int response_set_content_type(response_t *rs, const char *mime_type);
int response_set_content_length(response_t *rs, size_t sz);
int response_set_content_encoding(response_t *rs, const char *encoding);
int response_set_last_modified(response_t *rs, time_t mtime);
int response_set_date(response_t *rs, time_t now);
int response_del_field(response_t *rs, const char *name);

int response_set_cookie(response_t *rs, const char *name, const char *value,
    time_t expire, const char *path, const char *domain, int secure);
enum {
    RESPONSE_COOKIE_SECURE = 1,
    RESPONSE_COOKIE_HTTPONLY = 2,
    RESPONSE_COOKIE_SAMESITE_LAX = 4,
    RESPONSE_COOKIE_SAMESITE_STRICT = 8,
    RESPONSE_COOKIE_SAMESITE_NONE = 16
};
int response_set_cookie_ex(response_t *rs, const char *name, const char *value,
    time_t expire, const char *path, const char *domain, int flags);

#ifdef __cplusplus
}
#endif 

#endif
