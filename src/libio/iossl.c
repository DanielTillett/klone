/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <klin/io.h>
#include <klin/ioprv.h>
#include <klin/timer.h>
#include <klin/tls.h>
#include <klin/tlsprv.h>
#include <u/libu.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct io_ssl_s
{
    struct io_s io; /* must be the first item */
    SSL *ssl;
    int fd;
    int flags;
};

typedef struct io_ssl_s io_ssl_t;

static ssize_t io_ssl_read(io_t *io_, char *buf, size_t size);
static ssize_t io_ssl_write(io_t *io_, const char *buf, size_t size);
static int io_ssl_close(io_t *io_);

int io_ssl_get_SSL(io_t *io, SSL **pssl)
{
    io_ssl_t *io_ssl = (io_ssl_t*)io;

    dbg_err_if(io_ssl == NULL);
    dbg_err_if(pssl == NULL);
    dbg_err_if(io_ssl->io.type != IO_TYPE_SSL);

    dbg_err_if(io_ssl->ssl == NULL);

    *pssl = io_ssl->ssl;

    return 0;
err:
    return ~0;
}

/* the socket is non-blocking: wait as OpenSSL asks after a call that
 * returned 'rc' (the alarms run meanwhile, and one may close the socket);
 * return 0 to call again, ~0 on a real error, 1 on a clean EOF */
static int io_ssl_retry(io_ssl_t *io_ssl, int rc)
{
    switch(SSL_get_error(io_ssl->ssl, rc))
    {
    case SSL_ERROR_WANT_READ:
        return timerm_wait(&io_ssl->fd, TIMERM_WAIT_READ) ? ~0 : 0;
    case SSL_ERROR_WANT_WRITE:
        return timerm_wait(&io_ssl->fd, TIMERM_WAIT_WRITE) ? ~0 : 0;
    case SSL_ERROR_ZERO_RETURN:
        return 1;
    case SSL_ERROR_SYSCALL:
        if(rc < 0 && errno == EINTR)
            return 0;
        return ~0;
    default:
        return ~0;
    }
}

/* the socket under the TLS stream (-1 once closed) */
int io_ssl_get_fd(io_t *io)
{
    io_ssl_t *io_ssl = (io_ssl_t*)io;

    dbg_return_if (io_ssl == NULL || io_ssl->io.type != IO_TYPE_SSL, -1);

    return io_ssl->fd;
}

/* bytes OpenSSL has decrypted and not yet handed out */
size_t io_ssl_pending(io_t *io)
{
    io_ssl_t *io_ssl = (io_ssl_t*)io;
    int n;

    dbg_return_if (io_ssl == NULL || io_ssl->io.type != IO_TYPE_SSL, 0);

    return (n = SSL_pending(io_ssl->ssl)) > 0 ? (size_t) n : 0;
}

static ssize_t io_ssl_read(io_t *io_, char *buf, size_t size)
{
    io_ssl_t *io_ssl = (io_ssl_t *) io_;
    int c, rc;

    dbg_err_if (io_ssl == NULL);
    dbg_err_if (buf == NULL);

    for(;;)
    {
        nop_err_if(io_ssl->fd < 0);     /* closed by an alarm */

        if((c = SSL_read(io_ssl->ssl, buf, (int) U_MIN(size, INT_MAX))) > 0)
            return c;

        /* 0 is an EOF, with or without the peer's close_notify */
        if((rc = io_ssl_retry(io_ssl, c)) != 0)
        {
            nop_err_if(c < 0 && rc != 1);
            return 0;
        }
    }

err:
    return -1;
}

static ssize_t io_ssl_write(io_t *io_, const char *buf, size_t size)
{
    io_ssl_t *io_ssl = (io_ssl_t *) io_;
    int c;

    dbg_err_if (io_ssl == NULL);
    dbg_err_if (buf == NULL);

    for(;;)
    {
        nop_err_if(io_ssl->fd < 0);     /* closed by an alarm */

        if((c = SSL_write(io_ssl->ssl, buf, (int) U_MIN(size, INT_MAX))) > 0)
            return c;

        nop_err_if(io_ssl_retry(io_ssl, c));
    }

err:
    return -1;
}

/* close the underlaying fd (may be called more then once) */
static int io_ssl_close(io_t *io_)
{
    io_ssl_t *io_ssl = (io_ssl_t *) io_;
    dbg_err_if(io_ssl == NULL);

    if(io_ssl->flags & IO_FD_CLOSE && io_ssl->fd != -1)
    {
#ifdef OS_WIN
        /* a Winsock socket, not a C runtime descriptor: close(2) would
           leave the connection open */
        closesocket(io_ssl->fd);
#else
        close(io_ssl->fd);
#endif
        io_ssl->fd = -1;
    }

    return 0;
err:
    return ~0;
}

/* free data alloc'ed by this io type */
static int io_ssl_free(io_t *io_)
{
    io_ssl_t *io_ssl = (io_ssl_t *) io_;
    dbg_err_if(io_ssl == NULL);

    /* tell the peer the data is complete (close_notify); not done in
       io_ssl_close(), which also ends timed out connections */
    if(io_ssl->ssl && io_ssl->fd != -1)
        (void) SSL_shutdown(io_ssl->ssl);

    dbg_if(io_ssl_close(io_));

    if(io_ssl->ssl)
    {
        SSL_free(io_ssl->ssl);
        io_ssl->ssl = NULL;
    }

    return 0;
err:
    return -1;
}

static int io_ssl_connect(io_ssl_t *io_ssl)
{
    int rc;

    /* the TLS handshake */
    while((rc = SSL_connect(io_ssl->ssl)) <= 0)
        warn_err_ifm(io_ssl_retry(io_ssl, rc), "TLS handshake error: %d",
            SSL_get_error(io_ssl->ssl, rc));

    return 0;
err:
    return ~0;
}

/* a client that does not finish the handshake in time is dropped */
enum { IO_SSL_HANDSHAKE_TIMEOUT = 10 };

static int io_ssl_cb_handshake_timeout(talarm_t *al, void *arg)
{
    u_unused_args(al);

    warn("TLS handshake timed out");
    dbg_if(io_ssl_close((io_t *) arg));

    return 0;
}

static int io_ssl_accept(io_ssl_t *io_ssl)
{
    talarm_t *al = NULL;
    int rc;

    dbg_err_if(timerm_add(IO_SSL_HANDSHAKE_TIMEOUT,
                io_ssl_cb_handshake_timeout, io_ssl, &al));

    /* the TLS handshake */
    while((rc = SSL_accept(io_ssl->ssl)) <= 0)
        warn_err_ifm(io_ssl_retry(io_ssl, rc), "TLS handshake error: %d",
            SSL_get_error(io_ssl->ssl, rc));

    timerm_del(al);

    return 0;
err:
    if(al)
        timerm_del(al);
    return ~0;
}

int io_ssl_create(int fd, int flags, int client_mode,
        struct tls_ctx_s *ctx, io_t **pio)
{
    SSL_CTX *ssl_ctx = (SSL_CTX *) ctx;     /* see klin/tls.h */
    io_ssl_t *io_ssl = NULL;
    long vfy;

    dbg_return_if (pio == NULL, ~0);
    dbg_return_if (ssl_ctx == NULL, ~0);

    dbg_err_if(io_create(io_ssl_t, (io_t**)&io_ssl));

    io_ssl->io.type = IO_TYPE_SSL;

    io_ssl->fd = fd;
    io_ssl->flags = flags;

    io_ssl->ssl = SSL_new(ssl_ctx);
    dbg_err_if(io_ssl->ssl == NULL);

    /* assign a working descriptor to the SSL stream */
    dbg_err_if(SSL_set_fd(io_ssl->ssl, fd) == 0);

    /* non-blocking, so that a read never waits in OpenSSL for the rest of a
       record (a timeout could not end it): io_ssl_retry() waits instead */
#ifdef OS_WIN
    {
        u_long on = 1;
        dbg_err_if(ioctlsocket(fd, FIONBIO, &on) != 0);
    }
#else
    dbg_err_sif(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1);
#endif

    io_ssl->io.read = io_ssl_read;
    io_ssl->io.write = io_ssl_write;
    io_ssl->io.close = io_ssl_close; 
    io_ssl->io.free = io_ssl_free; 
    io_ssl->io.size = 0;

    /* set the secure flag (encrypted connection) */
    io_ssl->io.is_secure = 1;
    
    /* the TLS handshake (bounded by the caller's alarm, if any) */
    if(client_mode)
        dbg_err_if(io_ssl_connect(io_ssl));
    else
        dbg_err_if(io_ssl_accept(io_ssl));

    *pio = (io_t*)io_ssl;

    return 0;
err:
    if(io_ssl && io_ssl->ssl)
    {
        #ifdef SSL_OPENSSL
        /* print a warning message for bad client certificates */
        if((vfy = SSL_get_verify_result(io_ssl->ssl)) != X509_V_OK)
            warn("SSL client cert verify error: %s", 
                X509_verify_cert_error_string(vfy));
        SSL_set_shutdown(io_ssl->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        #endif
    }
    if(io_ssl)
        io_free((io_t *)io_ssl);
    return ~0;
}

