/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <string.h>
#include <klin/klog.h>
#include <klin/context.h>
#include <klin/server.h>
#include <klin/ppc.h>
#include <klin/ppc_cmd.h>
#include <klin/server_ppc_cmd.h>
#include "server_s.h"

/* struct used for ppc command PPC_CMD_NOP */
struct ppc_nop_s
{
    int dummy;
};

typedef struct ppc_nop_s ppc_nop_t;

/* client function */
int server_ppc_cmd_nop(server_t *s)
{
    ppc_nop_t nop;

    nop_err_if(s == NULL);
    nop_err_if(s->ppc == NULL);

    memset(&nop, 0, sizeof(ppc_nop_t));

    /* send the command request */
    nop_err_if(ppc_write(s->ppc, ctx->pipc, PPC_CMD_NOP, (char*)&nop, 
        sizeof(nop)) < 0);

    return 0;
err:
    return ~0;
}

/* [parent] nop op */
int server_ppc_cb_nop(ppc_t *ppc, int fd, unsigned char cmd, char *data, 
    size_t size, void *vso)
{
    u_unused_args(ppc, fd, cmd, data, size, vso);

    u_dbg("ppc nop cmd callback");
    return 0;
}

