/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_HEADER_H_
#define _KLIN_HEADER_H_

#include <klin/field.h>
#include <klin/io.h>

#ifdef __cplusplus
extern "C" {
#endif 

/* load modes */
enum { 
    HLM_OVERRIDE,/** if a field with the same name already exists override it */
    HLM_KEEP,    /** if a field with the same name already exists keep it */
    HLM_ADD      /** if a field with the same name already exists add another 
                     field with the same name */
};

typedef struct
{
     fields_t fields;
     size_t nfields;
     field_t *cur;      /* last field returned by header_get_fieldn() ... */
     size_t curidx;     /* ... and its index (cur is NULL after a change) */
} header_t;

int header_create(header_t**);
int header_load(header_t*, io_t *);
int header_load_from_cgienv(header_t *h);
int header_load_ex(header_t *h , io_t *io, int mode);
int header_load_request(header_t *h, io_t *io, size_t max_fields,
        size_t max_line, size_t max_size, int *status);
int header_free(header_t*);
int header_add_field(header_t *h, field_t *f);
int header_del_field(header_t *h, field_t *f);
field_t* header_get_field(header_t *h, const char *name);
int header_clear(header_t *h);

const char* header_get_field_value(header_t *h, const char *name);
int header_has_token(header_t *h, const char *name, const char *token);

int header_set_field(header_t *h, const char *name, const char *value);

field_t* header_get_fieldn(header_t *h, size_t idx);
size_t header_field_count(header_t *h);

/* for(f = NULL; (f = header_next_field(h, name or NULL, f)); ) ... */
field_t* header_next_field(header_t *h, const char *name, field_t *prev);
size_t header_count_field(header_t *h, const char *name);

#ifdef __cplusplus
}
#endif 

#endif
