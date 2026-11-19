/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_PPC_COMMAND_H_
#define _KLIN_PPC_COMMAND_H_
#include <stdio.h>
#include <klin/server.h>

/* nop */
int server_ppc_cmd_nop(server_t *s);
int server_ppc_cb_nop(ppc_t *ppc, int fd, unsigned char cmd, char *data, 
    size_t size, void *vso);

/* add log */
int syslog_to_klog(int level);
int server_ppc_cmd_log_add(server_t *s, int level, const char *str);
int server_ppc_cb_log_add(ppc_t *ppc, int fd, unsigned char cmd, char *data, 
    size_t size, void *vso);

/* fork child */
int server_ppc_cmd_fork_child(server_t *s, backend_t *be);
int server_ppc_cb_fork_child(ppc_t *ppc, int fd, unsigned char cmd, char *data,
    size_t size, void *vso);

/* get log lines */
int server_ppc_cmd_log_get(server_t *s, size_t i, char *line);
int server_ppc_cb_log_get(ppc_t *ppc, int fd, unsigned char cmd, 
    char *data, size_t size, void *vso);

/* access_log */
int server_ppc_cmd_access_log(server_t *s, int bid, int vhostid,
        const char *str);
int server_ppc_cb_access_log(ppc_t *ppc, int fd, unsigned char cmd, char *data, 
    size_t size, void *vso);

#endif
