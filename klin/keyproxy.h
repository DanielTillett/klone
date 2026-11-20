/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_KEYPROXY_H_
#define _KLIN_KEYPROXY_H_

#include "klin_conf.h"

#ifdef SSL_OPENSSL
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the TLS key manager (doc/KEYMGR): the private key lives in a separate
 * process, workers sign through it (tls_keyproxy_use_key: tlsprv.h) */
int tls_keyproxy_is_manager(pid_t pid);
void tls_keyproxy_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* SSL_OPENSSL */
#endif
