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

/* struct used for ppc command PPC_CMD_LOG_GET */
struct ppc_log_get_s
{
    int bid;                        /* calling backend ID       */
    ssize_t i;                      /* i-th line                */
    char line[KLOG_LN_SZ + 1];      /* log line (klog_getln)    */
};

typedef struct ppc_log_get_s ppc_log_get_t;

/* client function; 'line' is at least KLOG_LN_SZ + 1 bytes (as for klog_getln) */
int server_ppc_cmd_log_get(server_t *s, size_t i, char *line)
{
    ppc_log_get_t plg;
    unsigned char cmd;

    nop_err_if (s == NULL);
    nop_err_if (s->ppc == NULL);
    nop_err_if (ctx->backend == NULL);
    nop_err_if (line == NULL);

    memset(&plg, 0, sizeof(ppc_log_get_t));

    plg.bid = ctx->backend->id;
    plg.i = i;
    plg.line[0] = 0;

    /* send the command request */
    dbg_err_if(ppc_write(s->ppc, ctx->pipc, PPC_CMD_LOG_GET, (char*)&plg, 
        sizeof(plg)) < 0);

    /* get the response */
    dbg_err_if(ppc_read(s->ppc, ctx->pipc, &cmd, (char*)&plg, sizeof(plg)) < 0);

    dbg_err_if(cmd != PPC_CMD_LOG_GET);

    nop_err_if(plg.i < 0); /* error or eof */

    /* copy-out the line */
    /* sizeof(line) was the size of the pointer: lines came back cut to 7
       characters */
    u_strlcpy(line, plg.line, sizeof plg.line);

    return 0;
err:
    return ~0;
}

/* [parent] get a log line */
int server_ppc_cb_log_get(ppc_t *ppc, int fd, unsigned char cmd, char *data, 
    size_t size, void *vso)
{
    server_t *s;
    ppc_log_get_t *plg;
    backend_t *be;
    klog_t *kl;

    u_unused_args(ppc, fd, cmd, size);

    dbg_err_if (vso == NULL);
    dbg_err_if (data == NULL);

    plg = (ppc_log_get_t *) data;
    s = (server_t *) vso;

    /* by default use server logger */
    kl = s->klog;

    /* get the logger obj of the calling backend (if any) */
    if(!server_get_backend_by_id(s, plg->bid, &be) && be->klog)
        kl = be->klog;

    /* get the log line */
    if(kl == NULL || klog_getln(kl, plg->i, plg->line))
        plg->i = -1; /* eof or error */

    /* send back the response */
    nop_err_if(ppc_write(s->ppc, fd, PPC_CMD_LOG_GET, (char*)plg, 
        sizeof(ppc_log_get_t)) < 0);

    return 0;
err:
    return ~0;
}

