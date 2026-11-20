/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_SANDBOX_H_
#define _KLIN_SANDBOX_H_

#ifdef __cplusplus
extern "C" {
#endif

/* process sandboxes (doc/SANDBOX): seccomp on Linux, pledge on OpenBSD */
int sandbox_worker(int exec, const char *extra);
int sandbox_keymgr(void);
int sandbox_check_allow(const char *extra);

#ifdef __cplusplus
}
#endif

#endif
