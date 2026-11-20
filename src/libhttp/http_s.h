/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_HTTP_S_H_
#define _KLIN_HTTP_S_H_
#include "klin_conf.h"
#include <u/libu.h>
#include <klin/os.h>
#include <klin/broker.h>
#include <klin/ses_prv.h>

#ifdef SSL_ON
#include <klin/tls.h>
#endif 

struct http_s 
{
    u_config_t *config;     /* server config                                 */
    broker_t *broker;       /* pages broker                                  */
    int ssl;                /* >0 when SSL is enabled                        */
#ifdef SSL_ON
    tls_ctx_t *ssl_ctx;     /* TLS context                                   */
#endif
    /* session options struct                        */
    session_opt_t *sess_opt;
    vhost_list_t *vhosts;
    /* persistent connections (keep-alive) */
    int keep_alive;         /* !0 if enabled                                 */
    int ka_timeout;         /* secs to wait for the next request             */
    int ka_max;             /* max requests per connection                   */
    /* HTTP authentication: signs the Digest nonces (auth.c) */
    unsigned char auth_secret[32];
    /* caps on connections per client and on SSE/WebSocket ones (conntab) */
    int conn_class;
};

/* http.c */
int http_path_join(char *dst, size_t sz, const char *dir, const char *uri);
int http_load_aliases(vhost_t *vhost);

/* files.c: open a file resolved for a request (doc/FILES) */
int http_open_file(http_t *h, request_t *rq, const char *fqn, int flags);

#endif
