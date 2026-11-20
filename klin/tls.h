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

#ifdef __cplusplus
extern "C" {
#endif

/* a TLS server context (an SSL_CTX of the backend, see doc/CRYPTO) */
struct tls_ctx_s;
typedef struct tls_ctx_s tls_ctx_t;

int tls_init (void);
tls_ctx_t *tls_load_init_ctx (u_config_t *);
void tls_ctx_free (tls_ctx_t *);

#ifdef __cplusplus
}
#endif 

#endif /* SSL_ON */

#endif /* !_KLIN_TLS_H */
