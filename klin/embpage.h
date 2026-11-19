/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_EMB_PAGE_H_
#define _KLIN_EMB_PAGE_H_

#include <klin/page.h>
#include <u/libu.h>

#ifdef __cplusplus
extern "C" {
#endif 

void register_page(page_t *pg);
void unregister_page(page_t *pg);

#ifdef __cplusplus
}
#endif 

#endif
