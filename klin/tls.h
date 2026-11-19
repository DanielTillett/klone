/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_TLS_H_
#define _KLIN_TLS_H_

#include "klin_conf.h"
#include <u/libu.h>
#ifdef SSL_ON
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

int tls_init (void);
SSL_CTX *tls_load_init_ctx (u_config_t *);

#ifdef __cplusplus
}
#endif 

#endif /* SSL_ON */

#endif /* !_KLIN_TLS_H */
