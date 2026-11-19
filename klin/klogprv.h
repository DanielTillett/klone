/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_LOGPRV_H_
#define _KLIN_LOGPRV_H_

#include <klin/klog.h>

#ifdef __cplusplus
extern "C" {
#endif 

/* level names, indexed by KLOG_DEBUG .. KLOG_EMERG */
extern const char *kloglev[];

/* common */
int klog_new (int type, int threshold, const char *ident, klog_t **pkl);
int klog_open_mem (klog_t *kl, size_t ln_max);
int klog_open_syslog (klog_t *kl, int fac, int logopt);
int klog_open_file (klog_t *kl, const char *base, size_t npages, size_t nlines);
const char *klog_to_str (int lev);

#ifdef __cplusplus
}
#endif 

#endif /* _KLIN_LOGPRV_H_ */
