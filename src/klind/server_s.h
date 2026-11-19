/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_SERVER_S_H_
#define _KLIN_SERVER_S_H_
#include <signal.h>
#include <stdlib.h>
#include <klin/ppc.h>
#include <klin/backend.h>
#include <klin/klog.h>
#include <klin/timer.h>
#include <klin_conf.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SELECT
#include <sys/select.h>
#endif
#include <u/libu.h>
#include "child.h"

enum { SERVER_MAX_CHILD_COUNT = 1024 };

struct server_s 
{
    u_config_t *config;     /* server config                                */
    ppc_t *ppc;             /* parent procedure call                        */
    backends_t bes;         /* backend list                                 */
    klog_t *klog;           /* klog device                                  */
    talarm_t *al_klog_flush;/* klog flush alarm                             */
    children_t *children;   /* children list                                */
    fd_set rdfds, wrfds, exfds;
    const char *chroot;     /* server chroot dir                            */
    int uid, gid;           /* uid/gid used to run the server               */
    int hfd;                /* highest set fd in fd_sets                    */
    size_t nbackend;        /* # of servers                                 */
    size_t max_child;       /* max # of children                            */
    volatile sig_atomic_t stop; /* >0 will stop the loop (set by signals)   */
    int model;              /* server model                                 */
    int klog_flush;         /* >0 if this process flushes the klog          */
    int allow_root;         /* >0 allow root as the owner of klind process */
    int blind_chroot;       /* if blind chroot mode is enabled or disabled  */
};

int server_get_backend_by_id(server_t *s, int id, backend_t **pbe);
int server_spawn_child(server_t *s, backend_t *be);
int server_cb_klog_flush(talarm_t *a, void *arg);

#endif
