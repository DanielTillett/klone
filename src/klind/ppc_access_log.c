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
#include <klin/vhost.h>
#include <klin/server_ppc_cmd.h>
#include "server_s.h"

/* struct used for ppc command PPC_CMD_LOG_ADD */
struct ppc_access_log_s
{
    int bid;                        /* calling backend ID       */
    int vhostid;                    /* vhost ID                 */
    char log[U_MAX_LOG_LENGTH];     /* log line                 */
};

typedef struct ppc_access_log_s ppc_access_log_t;

/* client function */
int server_ppc_cmd_access_log(server_t *s, int bid, int vhostid,
        const char *str)
{
    ppc_access_log_t la;

    nop_err_if (s == NULL);
    nop_err_if (s->ppc == NULL);
    nop_err_if (str == NULL);

    memset(&la, 0, sizeof(ppc_access_log_t));

    la.bid = bid;
    la.vhostid = vhostid;
    (void) u_strlcpy(la.log, str, sizeof la.log);

    /* send the command request */
    nop_err_if(ppc_write(s->ppc, ctx->pipc, PPC_CMD_ACCESS_LOG, (char*)&la, 
        sizeof(la)) < 0);

    return 0;
err:
    return ~0;
}

/* [parent] log a new message */
int server_ppc_cb_access_log(ppc_t *ppc, int fd, unsigned char cmd, char *data, 
    size_t size, void *vso)
{
    server_t *s;
    ppc_access_log_t *pla;
    backend_t *be;
    vhost_t *vhost;
    vhost_list_t *vhost_list;
    http_t *http = NULL;

    u_unused_args(ppc, fd, cmd, size);

    nop_err_if (vso == NULL);
    nop_err_if (data == NULL);

    pla = (ppc_access_log_t*) data;
    s = (server_t *) vso;

    /* get the http object: a worker could send any backend id (and the
       pointer was left unset when it matched none: found by clang-tidy) */
    dbg_err_if(server_get_backend_by_id(s, pla->bid, &be) || be->arg == NULL);
    http = (http_t*)be->arg;

    dbg_err_if((vhost_list = http_get_vhost_list(http)) == NULL);

    dbg_err_if((vhost = vhost_list_get_n(vhost_list, pla->vhostid)) == NULL);

    /* log the line */
    if(vhost->klog)
        nop_err_if(klog(vhost->klog, KLOG_INFO, "%s", pla->log));

    return 0;
err:
    return ~0;
}

