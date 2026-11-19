/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <u/libu.h>
#include <klin/ppc.h>

struct ppc_header_s
{
    unsigned char cmd;
    size_t size;
};

typedef struct ppc_header_s ppc_header_t;

struct ppc_s
{
    ppc_cb_t ftb[256];  /* function pointers            */
    void *arg[256];     /* opaque function arguments    */
};

int ppc_register(ppc_t *ppc, unsigned char cmd, ppc_cb_t cb, void *arg)
{
    dbg_err_if (ppc == NULL);
    dbg_err_if (cb == NULL);

    ppc->ftb[cmd] = cb;
    ppc->arg[cmd] = arg;

    return 0;
err:
    return ~0;
}

/* read exactly 'size' bytes (a stream may return fewer per read); return
 * size, 0 on EOF before any byte, -1 on error or EOF in the middle */
static ssize_t ppc_do_read(int fd, char *data, size_t size)
{
    size_t done = 0;
    ssize_t n;

    dbg_return_if (fd < 0, -1);
    dbg_return_if (data == NULL, -1);

    while(done < size)
    {
        n = read(fd, data + done, size - done);
        if(n < 0 && errno == EINTR)
            continue;
        if(n <= 0)
            return (n == 0 && done == 0) ? 0 : -1;
        done += (size_t) n;
    }

    return (ssize_t) size;
}

/* write all of 'data' */
static ssize_t ppc_do_write(int fd, const char *data, size_t size)
{
    size_t done = 0;
    ssize_t n;

    dbg_return_if (fd < 0, -1);
    dbg_return_if (data == NULL, -1);

    while(done < size)
    {
        n = write(fd, data + done, size - done);
        if(n < 0 && errno == EINTR)
            continue;
        if(n <= 0)
            return -1;
        done += (size_t) n;
    }

    return (ssize_t) size;
}

/* send a command: header and data go out in one write(2), so a command sent
 * from a signal handler (the SIGALRM watchdog asks for a new child) cannot
 * land between the two parts of another one */
ssize_t ppc_write(ppc_t *ppc, int fd, unsigned char cmd, const char *data,
    size_t size)
{
    char msg[sizeof(ppc_header_t) + PPC_MAX_DATA_SIZE];
    ppc_header_t h;

    dbg_return_if (ppc == NULL, -1);
    dbg_return_if (data == NULL, -1);
    dbg_return_if (fd < 0, -1);
    dbg_return_if (size > PPC_MAX_DATA_SIZE, -1);

    memset(&h, 0, sizeof(ppc_header_t));
    h.cmd = cmd;
    h.size = size;

    memcpy(msg, &h, sizeof h);
    memcpy(msg + sizeof h, data, size);

    if(ppc_do_write(fd, msg, sizeof h + size) < 0)
        return -1;

    return 1;
}

ssize_t ppc_read(ppc_t *ppc, int fd, unsigned char *pcmd, char *data, 
    size_t size)
{
    ppc_header_t h;
    ssize_t n;

    dbg_return_if (ppc == NULL, -1);
    dbg_return_if (pcmd == NULL, -1);
    dbg_return_if (data == NULL, -1);
    dbg_return_if (fd < 0, -1);

    n = ppc_do_read(fd, (char*)&h, sizeof(ppc_header_t));
    if(n <= 0) /* error or eof */
        return n;

    /* buffer too small or cmd bigger then max allowed size */
    dbg_return_ifm (h.size > size || h.size > PPC_MAX_DATA_SIZE, -1,
            "ppc error h.cmd: %d, h.size: %lu", h.cmd, (unsigned long) h.size); 

    n = ppc_do_read(fd, data, h.size);
    if(n < 0 || (n == 0 && h.size)) /* error, or eof after the header */
        return -1;

    *pcmd = h.cmd;

    return h.size;
}

int ppc_dispatch(ppc_t *ppc, int fd, unsigned char cmd, char *data, size_t size)
{
    dbg_err_if (ppc == NULL);
    dbg_err_if (ppc->ftb[cmd] == NULL);

    ppc->ftb[cmd](ppc, fd, cmd, data, size, ppc->arg[cmd]);

    return 0;
err:
    return ~0;
}

int ppc_free(ppc_t *ppc)
{
    U_FREE(ppc);
    return 0;
}

int ppc_create(ppc_t **pppc)
{
    ppc_t *ppc = NULL;

    dbg_err_if (pppc == NULL);
    
    ppc = u_zalloc(sizeof(ppc_t));
    dbg_err_if(ppc == NULL);

    *pppc = ppc;

    return 0;
err:
    return ~0;
}

