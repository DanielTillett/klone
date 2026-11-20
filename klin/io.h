/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_IO_H_ 
#define _KLIN_IO_H_

#include "klin_conf.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <klin/codec.h>

#ifdef __cplusplus
extern "C" {
#endif 

struct io_s;
typedef struct io_s io_t;

struct tls_ctx_s;   /* klin/tls.h */

enum io_type_e
{
    IO_TYPE_FD,
    IO_TYPE_MEM,
#ifdef SSL_ON
    IO_TYPE_SSL
#endif
};

enum io_fd_flags {
    IO_FD_NO_FLAGS,
    IO_FD_CLOSE /* close(2) fd on io_free           */
};

enum io_mem_flags {
    IO_MEM_NO_FLAGS,
    IO_MEM_FREE_BUF     /* free(3) io mem buf on io_free    */
};

int io_fd_create(int fd, int flags, io_t **pio);
int io_mem_create(char *buf, size_t size, int flags, io_t **pio);
#ifdef SSL_ON
int io_ssl_create(int fd, int flags, int client_mode,
        struct tls_ctx_s *ctx, io_t **pio);
int io_ssl_get_fd(io_t *io_ssl);
size_t io_ssl_pending(io_t *io_ssl);
#endif
int io_fd_get_d(io_t *);
int io_get_fd(io_t *io);
size_t io_pending(io_t *io);
char* io_mem_get_buf(io_t *);
size_t io_mem_get_bufsz(io_t *io);

enum io_type_e io_type(io_t *io);

int io_close(io_t *io);
int io_free(io_t *io);
int io_dup(io_t *io, io_t **pio);
int io_name_set(io_t *io, const char* name);
int io_name_get(io_t *io, char* name, size_t sz);
ssize_t io_read(io_t *io, char* buf, size_t size);
ssize_t io_write(io_t *io, const char* buf, size_t size);
ssize_t io_flush(io_t *io);
ssize_t io_seek(io_t *io, size_t off);
ssize_t io_tell(io_t *io);
ssize_t io_copy(io_t *out, io_t *in, size_t size);
ssize_t io_pipe(io_t *out, io_t *in);
ssize_t io_gets(io_t *io, char *buf, size_t size);
ssize_t io_get_until(io_t *io, char stop_at, char *buf, size_t size);
ssize_t io_getc(io_t *io, char *c);
ssize_t io_printf(io_t *io, const char* fmt, ...);
ssize_t io_vprintf(io_t *io, const char *fmt, va_list ap);
ssize_t io_putc(io_t *io, char c);
int io_codec_add_head(io_t *io, codec_t* codec);
int io_codec_add_tail(io_t *io, codec_t* codec);
int io_codecs_remove(io_t *io);
int io_codecs_discard(io_t *io);
int io_has_codecs(io_t *io);
void io_set_write_codecs(io_t *io, int on);
void io_set_read_limit(io_t *io, ssize_t limit);
int io_set_write_buffer_size(io_t *io, size_t size);
size_t io_get_read_count(io_t *io);
int io_is_secure(io_t *io);

#ifdef __cplusplus
}
#endif 

#endif
