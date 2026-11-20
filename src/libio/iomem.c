/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <unistd.h>
#include <u/libu.h>
#include <klin/io.h>
#include <klin/ioprv.h>

struct io_mem_s
{
    struct io_s io; /* must be the first item */
    char *buf;
    size_t size;
    size_t off;
    int flags;
};

typedef struct io_mem_s io_mem_t;

static ssize_t io_mem_read(io_t *io_, char *buf, size_t size);
static ssize_t io_mem_write(io_t *io_, const char *buf, size_t size);
static ssize_t io_mem_seek(io_t *io_, size_t off);
static ssize_t io_mem_tell(io_t *io_);
static int io_mem_close(io_t *io_);
static int io_mem_free(io_t *io_);

static ssize_t io_mem_tell(io_t *io_)
{
    io_mem_t *im = (io_mem_t *) io_;
    dbg_return_if (im == NULL, -1);

    return im->off;
}

static ssize_t io_mem_seek(io_t *io_, size_t off)
{
    io_mem_t *im = (io_mem_t *) io_;
    dbg_return_if (im == NULL, -1);
    
    if(off > im->size)
        return -1;

    im->off = off;

    return off;
}

static ssize_t io_mem_read(io_t *io_, char *buf, size_t size)
{
    io_mem_t *im = (io_mem_t *) io_;
    char *ptr;
    size_t sz;

    dbg_return_if (im == NULL, -1);
    dbg_return_if (buf == NULL, -1);

    sz = U_MIN(size, im->size - im->off);
    if(sz)
    {
        ptr = im->buf + im->off; 
        memcpy(buf, ptr, sz);
        im->off += sz;
    }

    return sz;
}

static ssize_t io_mem_write(io_t *io_, const char *buf, size_t size)
{
    io_mem_t *im = (io_mem_t *) io_;
    char *ptr;
    size_t sz;

    dbg_return_if (im == NULL, -1);
    dbg_return_if (buf == NULL, -1);

    sz = U_MIN(size, im->size - im->off);
    if(sz)
    {
        ptr = im->buf + im->off; 
        memcpy(ptr, buf, sz);
        im->off += sz;
    }

    return sz;
}

static int io_mem_close(io_t *io_)
{
    io_mem_t *im = (io_mem_t *) io_;
    u_unused_args(im);
    return 0;
}

static int io_mem_free(io_t *io_)
{
    io_mem_t *im = (io_mem_t *) io_;
    dbg_return_if (im == NULL, ~0);

    if(im->flags & IO_MEM_FREE_BUF)
    {
        U_FREE(im->buf);
        im->buf = NULL;
        im->size = im->off = 0;
    }

    return 0;
}

size_t io_mem_get_bufsz(io_t *io)
{
    io_mem_t *im = (io_mem_t*)io;

    dbg_err_if(io == NULL);
    dbg_err_if(im->io.type != IO_TYPE_MEM);

    return im->size;
err:
    return 0;
}

char *io_mem_get_buf(io_t *io)
{
    io_mem_t *im = (io_mem_t*)io;

    dbg_err_if(io == NULL);
    dbg_err_if(im->io.type != IO_TYPE_MEM);

    return im->buf;
err:
    return NULL;
}

int io_mem_create(char *buf, size_t size, int flags, io_t **pio)
{
    io_mem_t *im = NULL;

    dbg_err_if (buf == NULL);
    dbg_err_if (pio == NULL);
    
    dbg_err_if(io_create(io_mem_t, (io_t**)&im));

    im->io.type = IO_TYPE_MEM;

    im->buf = buf;
    im->size = size;
    im->flags = flags;
    im->off = 0;
    im->io.read = io_mem_read;
    im->io.write = io_mem_write;
    im->io.seek = io_mem_seek;
    im->io.tell = io_mem_tell;
    im->io.close = io_mem_close; 
    im->io.free = io_mem_free; 

    *pio = (io_t*)im;

    return 0;
err:
    if(im)
        io_free((io_t *)im);
    return ~0;
}
