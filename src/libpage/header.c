/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <string.h>
#include <u/libu.h>
#include <klin/os.h>
#include <klin/header.h>
#include <klin/http.h>
#include <klin/utils.h>

/**
 * \ingroup header
 * \brief   Set the value of a field in a header
 *
 * Set the value of field \p name to \p value in header \p h.
 *
 * \param h     header object
 * \param name  name of the field
 * \param value value of the field
 *
 * \return \c 0 if successful, non-zero on error
 */
int header_set_field(header_t *h, const char *name, const char *value)
{
    field_t* n = NULL, *ex;

    dbg_err_if (h == NULL);
    dbg_err_if (name == NULL);
    dbg_err_if (value == NULL);

    /* modify existing field if already set */
    if((ex = header_get_field(h, name)) == NULL)
    {
        dbg_err_if(field_create(name, value, &n));
        dbg_err_if(header_add_field(h, n));
    } else
        dbg_err_if(field_set(ex, name, value));

    return 0;
err:
    if(n)
        field_free(n);
    return ~0;
}

/**
 * \ingroup header
 * \brief   Clear a header
 *
 * Clear all items in header \p h.
 *
 * \param h    header object
 *
 * \return \c 0 if successful, non-zero on error
 */
int header_clear(header_t *h)
{
    field_t *f;
    
    dbg_return_if (h == NULL, ~0);
    
    /* free all items */
    while((f = TAILQ_FIRST(&h->fields)) != NULL)
    {
        header_del_field(h, f);
        field_free(f);
    }

    return 0;
}

/**
 * \ingroup header
 * \brief   Count fields in a header
 *
 * Return the number of fields in header \p h.
 *
 * \param h    header object
 *
 * \return the number of fields found in \p h
 */
size_t header_field_count(header_t *h)
{
    dbg_return_if (h == NULL, 0);

    return h->nfields;
}

/** 
 * \ingroup header
 * \brief   Get ith field in a header
 *  
 * Return the \c field_t object at index \p idx in header \p h.
 *
 * \param h    header object
 * \param idx  index
 *  
 * \return the pointer to the field or \c NULL if no field could be found
 */
field_t *header_get_fieldn(header_t *h, size_t idx)
{
    field_t *f;
    size_t i = 0;

    dbg_goto_if (h == NULL, notfound);
    nop_goto_if (idx >= h->nfields, notfound);

    /* fields are usually read in order (for i in 0..n): go on from the last
       one returned instead of walking the list from the start every time */
    if(h->cur && idx >= h->curidx)
    {
        f = h->cur;
        i = h->curidx;
    } else
        f = TAILQ_FIRST(&h->fields);

    for(; f; f = TAILQ_NEXT(f, np), ++i)
    {
        if(i == idx)
        {
            h->cur = f;
            h->curidx = i;
            return f;
        }
    }

notfound:
    return NULL;
}

/** 
 * \ingroup header
 * \brief   Get a field given a name
 *  
 * Return the first matching \c field_t object with name \p name in header \p h
 *
 * \param h     header object
 * \param name  name of the field to be searched
 *  
 * \return
 *  - the field string corresponding to \p name
 *  - \c NULL if no field could be found
 */
field_t *header_get_field(header_t *h, const char *name)
{
    field_t *f = NULL;

    dbg_goto_if (h == NULL, notfound);
    dbg_goto_if (name == NULL, notfound);

    TAILQ_FOREACH(f, &h->fields, np)
        if(strcasecmp(f->name, name) == 0)
            return f;

notfound:
    return NULL;
}

/**
 * \ingroup header
 * \brief   Iterate over the fields of a header (all, or those with a name)
 *
 * Return the first field after \p prev (from the start if \p prev is
 * \c NULL) whose name is \p name (case-insensitive), or any field if \p name
 * is \c NULL:
 *
 * \code
 *  for(f = NULL; (f = header_next_field(h, "Cookie", f)) != NULL; )
 *      ...
 * \endcode
 *
 * The header must not change during the loop.
 *
 * \param h     header object
 * \param name  name of the fields to return, or \c NULL for all
 * \param prev  the field returned by the previous call, or \c NULL
 *
 * \return the next matching field, or \c NULL when there are no more
 */
field_t *header_next_field(header_t *h, const char *name, field_t *prev)
{
    field_t *f;

    dbg_return_if (h == NULL, NULL);

    for(f = prev ? TAILQ_NEXT(prev, np) : TAILQ_FIRST(&h->fields); f;
            f = TAILQ_NEXT(f, np))
    {
        if(name == NULL || (f->name && !strcasecmp(f->name, name)))
            return f;
    }

    return NULL;
}

/**
 * \ingroup header
 * \brief   Count the fields with a given name
 *
 * \param h     header object
 * \param name  name of the fields (case-insensitive)
 *
 * \return the number of fields called \p name in \p h
 */
size_t header_count_field(header_t *h, const char *name)
{
    field_t *f;
    size_t n = 0;

    dbg_return_if (name == NULL, 0);

    for(f = NULL; (f = header_next_field(h, name, f)) != NULL; )
        ++n;

    return n;
}

/**
 * \ingroup header
 * \brief   Get field value
 *  
 * Return a string representation of the field with name \p name in header \p h
 *
 * \param h     header object
 * \param name  name of the field
 *  
 * \return
 *  - the field string corresponding to \p name
 *  - \c NULL if no field could be found
 */
const char *header_get_field_value(header_t *h, const char *name)
{
    field_t *f;

    dbg_return_if (h == NULL, NULL);
    dbg_return_if (name == NULL, NULL);
    
    f = header_get_field(h, name);

    return f ? field_get_value(f) : NULL;
}

/**
 * \ingroup header
 * \brief   Tell if a list-valued field contains a token
 *
 * Look for \p token (case-insensitive) in the comma-separated value of the
 * field \p name, e.g. "close" in "Connection: keep-alive, close".
 *
 * \param h      header object
 * \param name   name of the field
 * \param token  token to look for
 *
 * \return \c 1 if the token is found, \c 0 otherwise (or if the field is
 *         missing)
 */
int header_has_token(header_t *h, const char *name, const char *token)
{
    const char *v;
    field_t *f;
    size_t len;

    dbg_return_if (h == NULL, 0);
    dbg_return_if (name == NULL, 0);
    dbg_return_if (token == NULL, 0);

    len = strlen(token);

    /* the field may be repeated: look in every instance */
    for(f = NULL; (f = header_next_field(h, name, f)) != NULL; )
    {
        for(v = field_get_value(f); v && *v; ++v)
        {
            while(*v == ' ' || *v == '\t' || *v == ',')
                ++v;
            if(!strncasecmp(v, token, len) &&
                    (v[len] == '\0' || v[len] == ',' || v[len] == ' ' ||
                     v[len] == '\t'))
                return 1;
            if((v = strchr(v, ',')) == NULL)
                break;
        }
    }

    return 0;
}

/** 
 * \ingroup header
 * \brief   Delete a field from a header
 *  
 * Delete the supplied field \p f in header \p h.
 *
 * \param h  header object
 * \param f  field to be deleted
 *  
 * \return \c 0 on success, non-zero otherwise
 */
int header_del_field(header_t *h, field_t *f)
{
    dbg_return_if (h == NULL, ~0);
    dbg_return_if (f == NULL, ~0);

    TAILQ_REMOVE(&h->fields, f, np);
    h->nfields--;
    h->cur = NULL;

    return 0;
}

/** 
 * \ingroup header
 * \brief   Add a field to a header
 *  
 * Add a field \p f to header \p h.
 *
 * \param h  header object
 * \param f  field to be added
 *  
 * \return \c 0 on success, non-zero otherwise
 */
int header_add_field(header_t *h, field_t *f)
{
    dbg_return_if (h == NULL, ~0);
    dbg_return_if (f == NULL, ~0);

    TAILQ_INSERT_TAIL(&h->fields, f, np);
    h->nfields++;
    h->cur = NULL;

    return 0;
}

static int header_process_line(header_t *h, const char *line, int mode)
{
    field_t *ex, *f = NULL;

    dbg_err_if (h == NULL);
    dbg_err_if (line == NULL);

    if(line[0] == '\0')
        return 0;

    /* alloc a new field */
    dbg_err_if(field_create(NULL, NULL, &f));

    /* parse and set name, value and params */
    dbg_err_if(field_set_from_line(f, line));

    /* add to this header */
    switch(mode)
    {
    case HLM_ADD:
        dbg_err_if(header_add_field(h, f));
        break;
    case HLM_OVERRIDE:
        if((ex = header_get_field(h, field_get_name(f))) != NULL)
        {
            header_del_field(h, ex);
            field_free(ex); ex = NULL;
        }
        dbg_err_if(header_add_field(h, f));
        break;
    case HLM_KEEP:
        if((ex = header_get_field(h, field_get_name(f))) == NULL)
            dbg_err_if(header_add_field(h, f));
        else {
            field_free(f); f = NULL;
        }
        break;
    default:
        crit_err("unknown header load mode");
    }

    return 0;
err:
    if(f)
        field_free(f);
    return ~0;
}

/* load from environment. change each HTTP_name=value to name=value (replacing
   '_' with '-' */
int header_load_from_cgienv(header_t *h)
{
    extern char **environ;
    enum { BUFSZ = 256 };
    int i;
    size_t blen, t;
    char *e, *eq, buf[BUFSZ];

    /* add HTTP_* to header field list */
    for(i = 0; environ[i]; ++i)
    {
        e = environ[i];
        if(strlen(e) > 5 && strncmp("HTTP_", e, 5) == 0)
        {
            memset(buf, 0, sizeof(buf));

            /* make a copy of e so we can modify it */
            u_strlcpy(buf, e + 5, sizeof buf);

            eq = strchr(buf, '=');
            if(eq == NULL)
                continue; /* malformed */

            *eq = 0; /* put a \0 between name and value */

            /* subst '_' with '-' */
            for(t = 0, blen = strlen(buf); t < blen; ++t)
                if(buf[t] == '_')
                    buf[t] = '-';

            dbg_if(header_set_field(h, buf, 1 + eq));
        }
    }

    return 0;
}

int header_load_ex(header_t *h, io_t *io, int mode)
{
    enum { MAX_FIELDS = 256, MAX_LINE = 8192, MAX_TOTAL = 65536 };
    /* a line, its '\n' and one more byte to tell that it is too long */
    char text[MAX_LINE + 2];
    size_t count = 0, total = 0, len;
    ssize_t rc;

    dbg_err_if(h == NULL || io == NULL);
    for (;;)
    {
        /* each line is read straight from the io buffer and parsed in
           place: no string object to grow and free for every line */
        rc = io_get_until(io, '\n', text, sizeof(text));
        dbg_err_if(rc <= 0);    /* EOF or a read error */
        len = (size_t) rc;
        /* too long, or EOF before the end of the line */
        dbg_err_if(len > MAX_LINE || text[len - 1] != '\n');
        dbg_err_if(memchr(text, '\0', len) != NULL);
        dbg_err_if(len > MAX_TOTAL - total);
        total += len;
        text[--len] = '\0';
        if (len && text[len - 1] == '\r')
            text[--len] = '\0';
        if (len == 0)
            break;
        /* Obsolete line folding and embedded CR are ambiguous to proxies. */
        dbg_err_if(u_isblank(text[0]) || memchr(text, '\r', len) != NULL);
        dbg_err_if(++count > MAX_FIELDS);
        dbg_err_if(header_process_line(h, text, mode));
    }
    return 0;
err:
    return ~0;
}

/* RFC 9110 token characters (a field name) */
static int header_is_tchar(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || (c && strchr("!#$%&'*+-.^_`|~", c));
}

/* "name: value" with a token name right before the colon, and no control
   characters but HTAB in the value */
static int header_line_ok(const char *line, size_t len)
{
    const unsigned char *p = (const unsigned char *) line,
          *end = p + len, *colon = memchr(p, ':', len);

    if(colon == NULL || colon == p)
        return 0;
    for(; p < colon; ++p)
        if(!header_is_tchar(*p))
            return 0;
    for(++p; p < end; ++p)
        if((*p < 0x20 && *p != '\t') || *p == 0x7f)
            return 0;
    return 1;
}

/**
 * \ingroup header
 * \brief   Load the header of a request, within limits
 *
 * Like header_load(), but a request header must be well formed: CRLF (or
 * LF) lines of "name: value" with a token name and no control characters,
 * no obsolete line folding, at most \p max_fields fields of at most
 * \p max_line bytes each and \p max_size bytes in all.
 *
 * \param h           header object
 * \param io          the client connection
 * \param max_fields  most fields
 * \param max_line    most bytes in one field line (with its CRLF)
 * \param max_size    most bytes in the whole header (with the blank line)
 * \param status      on failure: 431 for a limit, 400 for a bad line, 0 if
 *                    the client closed the connection or timed out
 *
 * \return \c 0 on success, non-zero otherwise
 */
int header_load_request(header_t *h, io_t *io, size_t max_fields,
        size_t max_line, size_t max_size, int *status)
{
    enum { LINE_BUF = 65536 };
    char *text = NULL;
    size_t count = 0, total = 0, len;
    ssize_t rc;

    dbg_err_if(h == NULL || io == NULL || status == NULL);
    *status = 0;
    max_line = U_MIN(U_MAX(max_line, 64), LINE_BUF - 2);
    dbg_err_if((text = u_malloc(max_line + 2)) == NULL);

    for (;;)
    {
        /* a line, its '\n' and one more byte to tell that it is too long */
        rc = io_get_until(io, '\n', text, max_line + 2);
        nop_err_if(rc <= 0);    /* EOF, a read error or the deadline */
        len = (size_t) rc;
        if(text[len - 1] != '\n')
        {
            /* EOF before the end of the line, or a line too long */
            *status = (len > max_line) ? HTTP_STATUS_HEADER_TOO_LARGE : 0;
            goto err;
        }
        *status = HTTP_STATUS_HEADER_TOO_LARGE;
        nop_err_if(len > max_line || len > max_size - U_MIN(total, max_size));
        total += len;
        *status = HTTP_STATUS_BAD_REQUEST;
        nop_err_if(memchr(text, '\0', len) != NULL);
        text[--len] = '\0';
        if (len && text[len - 1] == '\r')
            text[--len] = '\0';
        if (len == 0)
            break;
        /* obsolete line folding, a bare CR, a blank or another character
           before the colon: each is read differently by some proxies */
        nop_err_if(!header_line_ok(text, len));
        *status = HTTP_STATUS_HEADER_TOO_LARGE;
        nop_err_if(++count > max_fields);
        *status = HTTP_STATUS_BAD_REQUEST;
        nop_err_if(header_process_line(h, text, HLM_ADD));
    }
    *status = 0;
    u_free(text);
    return 0;
err:
    U_FREE(text);
    return ~0;
}

int header_load(header_t *h , io_t *io)
{
    return header_load_ex(h, io, HLM_ADD);
}

int header_create(header_t **ph)
{
    header_t *h = NULL;

    dbg_err_if (ph == NULL);

    h = u_zalloc(sizeof(header_t));
    dbg_err_if(h == NULL);

    TAILQ_INIT(&h->fields);

    *ph = h;

    return 0;
err:
    return ~0;
}

int header_free(header_t *h)
{
    if (h)
    {
        (void) header_clear(h);
        U_FREE(h);
    }

    return 0;
}
