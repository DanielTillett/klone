/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_MIME_MAP_H_
#define _KLIN_MIME_MAP_H_
 
#ifdef __cplusplus
extern "C" {
#endif

typedef struct mime_map_s
{
    const char *ext, *mime_type;
    int comp;   /* if >0 compression is recommended */
} mime_map_t;

extern mime_map_t mime_map[];

#ifdef __cplusplus
}
#endif 

#endif
