/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <stdint.h>
#include <string.h>
#include <klin/field.h>
#include <klin/utils.h>
#include <u/libu.h>

int field_set(field_t*, const char *name, const char *value);
int field_set_from_line(field_t*, const char *line);
const char* field_get_name(field_t *f);
const char* field_get_value(field_t *f);

/* freed fields are kept, with their buffer, for the next field_create():
 * every request creates and frees the same few header fields (a process
 * serves one connection at a time, there are no threads) */
enum { FIELD_CACHE_MAX = 64, FIELD_BUF_KEEP = 256, FIELD_BUF_MIN = 64 };
static field_t *field_cache[FIELD_CACHE_MAX];
static size_t field_ncached = 0;

/* does 'p' point into the buffer of field 'f'? (compared as addresses: 'p'
   is usually some other object, and relational operators on pointers into
   different objects are undefined) */
static int field_in_buf(field_t *f, const char *p)
{
    uintptr_t a = (uintptr_t) p, b = (uintptr_t) f->buf;

    return p && f->buf && a >= b && a - b < f->bufsz;
}

/* store 'name' ('nlen' bytes) and 'value' in the field buffer, reused if
 * large enough; either may be NULL */
static int field_store(field_t *f, const char *name, size_t nlen,
        const char *value)
{
    size_t vlen = value ? strlen(value) : 0, need = nlen + vlen + 2;
    char *buf = f->buf;

    /* a new buffer if too small or if the new text comes from this one */
    if(need > f->bufsz || field_in_buf(f, name) || field_in_buf(f, value))
    {
        buf = u_malloc(U_MAX(need, FIELD_BUF_MIN));
        dbg_err_if(buf == NULL);
    }

    if(name)
        memcpy(buf, name, nlen);
    buf[nlen] = '\0';

    if(value)
        memcpy(buf + nlen + 1, value, vlen + 1);
    else
        buf[nlen + 1] = '\0';

    f->name = name ? buf : NULL;
    f->value = value ? buf + nlen + 1 : NULL;

    if(buf != f->buf)
    {
        U_FREE(f->buf);
        f->buf = buf;
        f->bufsz = U_MAX(need, FIELD_BUF_MIN);
    }

    return 0;
err:
    return ~0;
}

/* set field 'f' to the 'nlen' bytes long 'name' and to 'value' */
static int field_setn(field_t *f, const char *name, size_t nlen,
        const char *value)
{
    const unsigned char *p, *end;

    dbg_err_if (f == NULL);
    dbg_err_if (name == NULL);
    dbg_err_if (value == NULL);
    dbg_err_if (nlen == 0);
    end = (const unsigned char *)name + nlen;
    for (p = (const unsigned char *)name; p < end; ++p)
        dbg_err_if(!((*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
            (*p != '\0' && strchr("!#$%&'*+-.^_`|~", *p) != NULL)));
    for (p = (const unsigned char *)value; *p; ++p)
        dbg_err_if((*p < 32 && *p != '\t') || *p == 127);

    dbg_err_if(field_store(f, name, nlen, value));

    return 0;
err:
    return ~0;
}

/**
 * \ingroup header
 * \brief   Set a field
 *
 * Set field \p f to have \p name and \p value.
 *
 * \param f     field object
 * \param name  field name
 * \param value field value
 *
 * \return \c 0 if successful, non-zero on error
 */
int field_set(field_t *f, const char *name, const char *value)
{
    dbg_return_if (name == NULL, ~0);

    return field_setn(f, name, strlen(name), value);
}

/**
 * \ingroup header
 * \brief   Set a field from a line
 *
 * Set the name and value of field \p f.  Name and value must be separated by
 * \c ":".
 *
 * \param f     field object
 * \param ln    line
 *
 * \return \c 0 if successful, non-zero on error
 */
int field_set_from_line(field_t *f, const char *ln)
{
    const char *colon, *p;

    dbg_err_if (f == NULL);
    dbg_err_if (ln == NULL);
    dbg_err_if (!strlen(ln));

    dbg_err_if((colon = strchr(ln, ':')) == NULL);

    /* eat blanks between ':' and value */
    for(p = colon + 1; u_isblank(*p); ++p)
        ;

    dbg_err_if(field_setn(f, ln, colon - ln, p));

    return 0;
err:
    u_dbg("failed setting field from line: %s", ln);
    return ~0;
}

/**
 * \ingroup header
 * \brief   Get the name of a field
 *
 * Return the string value of field \p f.
 *
 * \param f     field object
 *
 * \return the (null-terminated) string corresponding to the field name
 */
const char* field_get_name(field_t *f)
{
    dbg_return_if (f == NULL, NULL);

    return f->name; /* may be null */
}

/**
 * \ingroup header
 * \brief   Get the value of a field
 *
 * Return the string value of field \p f.
 *
 * \param f     field object
 *
 * \return the (null-terminated) string corresponding to the field value
 */
const char* field_get_value(field_t *f)
{
    dbg_return_if (f == NULL, NULL);

    return f->value; /* may be null */
}

/**
 * \ingroup header
 * \brief   Create a field
 *
 * Create a field from \p name and \p value into \p *pf.
 *
 * \param name  field name
 * \param value field value
 * \param pf    address of field pointer
 *
 * \return \c 0 if successful, non-zero on error
 */
int field_create(const char *name, const char *value, field_t **pf)
{
    field_t *f = NULL;

    /* name and value may be NULL */
    dbg_err_if (pf == NULL);

    if(field_ncached)
    {
        /* reuse a freed field and its buffer */
        f = field_cache[--field_ncached];
        f->name = f->value = NULL;
    } else {
        f = u_zalloc(sizeof(field_t));
        dbg_err_if(f == NULL);
    }

    if (name && value)
    {
        dbg_err_if(field_set(f, name, value));
        *pf = f;
        return 0;
    }

    if(name || value)
        dbg_err_if(field_store(f, name, name ? strlen(name) : 0, value));

    *pf = f;

    return 0;
err:
    if(f)
        field_free(f);
    return ~0;
}

/**
 * \ingroup header
 * \brief   Free a field
 *
 * Free field \p f.
 *
 * \param f     field object
 *
 * \return \c 0, always
 */
int field_free(field_t *f)
{
    if(f)
    {
        /* keep it for the next field_create() if its buffer is small */
        if(field_ncached < FIELD_CACHE_MAX && f->bufsz <= FIELD_BUF_KEEP &&
                f->params == NULL)
        {
            f->name = f->value = NULL;
            field_cache[field_ncached++] = f;
            return 0;
        }

        U_FREE(f->buf);
        U_FREE(f);
    }

    return 0;
}
