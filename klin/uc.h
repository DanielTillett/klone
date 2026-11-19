/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_UC_H_
#define _KLIN_UC_H_

#ifdef __cplusplus
extern "C" {
#endif 

/* user-provided startup/term functions (--enable_uc configure arg is needed) */
void uc_init(void);
void uc_term(void);

#ifdef __cplusplus
}
#endif 

#endif

