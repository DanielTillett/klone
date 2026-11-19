/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_FIELD_H_
#define _KLIN_FIELD_H_

#include <sys/types.h>
#include <u/libu.h>

#ifdef __cplusplus
extern "C" {
#endif 

TAILQ_HEAD(param_list_s, param_s);
typedef struct param_s
{
    TAILQ_ENTRY(param_s) np; /* next & prev pointers */
    char *name;              /* param name           */
    char *value;             /* param value          */
} param_t;

typedef struct param_list_s params_t; /* param list */

TAILQ_HEAD(field_list_s, field_s);
typedef struct field_s
{
    TAILQ_ENTRY(field_s) np; /* next & prev pointers */
    char *name;              /* field name           */
    char *value;             /* field value          */
    params_t *params;        /* param list           */
    char *buf;               /* holds name and value */
    size_t bufsz;            /* ... and its size     */
} field_t;

/* field list */
typedef struct field_list_s fields_t; /* field list */

int field_create(const char* name, const char *value, field_t**);
int field_set(field_t*, const char *name, const char *value);
int field_set_from_line(field_t*, const char *line);
int field_free(field_t*);
const char* field_get_name(field_t *f);
const char* field_get_value(field_t *f);

#ifdef __cplusplus
}
#endif 

#endif
