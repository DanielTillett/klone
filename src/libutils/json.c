/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* JSON (RFC 8259) reader and writer (doc/JSON). The reader is strict: no
 * comments, trailing commas, single quotes or NaN; strings must be UTF-8,
 * and a key may appear once per object (two parsers reading the same
 * duplicate differently is a known way past validation). Nesting is
 * limited to JSON_MAX_DEPTH. */

#include "klin_conf.h"
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <u/libu.h>
#include <klin/json.h>

struct json_s
{
    json_type_t type;
    double num;
    int64_t ival;
    int is_int;             /* the number is an integer that fits ival */
    char *str;              /* string value, NUL-terminated            */
    size_t slen;
    json_t **items;         /* array or object members                 */
    char **keys;            /* object keys, parallel to items          */
    size_t *klens;
    size_t n, cap;
};

/* decode one UTF-8 sequence at s (avail bytes): the code point, and its
 * length; 0 if it is not well-formed (overlong, surrogate, past U+10FFFF,
 * cut short) */
static size_t json_utf8(const unsigned char *s, size_t avail, unsigned long *cp)
{
    size_t n, k;
    unsigned long c;

    if(avail == 0)
        return 0;
    if(s[0] < 0x80)
    {
        *cp = s[0];
        return 1;
    }
    if(s[0] >= 0xC2 && s[0] <= 0xDF)
        n = 2, c = s[0] & 0x1F;
    else if(s[0] >= 0xE0 && s[0] <= 0xEF)
        n = 3, c = s[0] & 0x0F;
    else if(s[0] >= 0xF0 && s[0] <= 0xF4)
        n = 4, c = s[0] & 0x07;
    else
        return 0;
    if(avail < n)
        return 0;
    for(k = 1; k < n; ++k)
    {
        if((s[k] & 0xC0) != 0x80)
            return 0;
        c = (c << 6) | (s[k] & 0x3F);
    }
    if((n == 3 && (c < 0x800 || (c >= 0xD800 && c <= 0xDFFF))) ||
            (n == 4 && (c < 0x10000 || c > 0x10FFFF)))
        return 0;
    *cp = c;
    return n;
}

/* ------------------------------------------------------------------------
 * reader
 * ---------------------------------------------------------------------- */

typedef struct
{
    const unsigned char *p, *end, *start;
    char *err;
    size_t errsz;
    int failed;
} json_parser_t;

static void json_fail(json_parser_t *ps, const char *what)
{
    if(!ps->failed && ps->err && ps->errsz)
        (void) snprintf(ps->err, ps->errsz, "%s at offset %lu", what,
                (unsigned long) (ps->p - ps->start));
    ps->failed = 1;
}

static void json_ws(json_parser_t *ps)
{
    while(ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' ||
                *ps->p == '\n' || *ps->p == '\r'))
        ps->p++;
}

static json_t *json_new(json_type_t type)
{
    json_t *j = u_zalloc(sizeof *j);

    if(j)
        j->type = type;
    return j;
}

static int json_push(json_t *j, json_t *item, char *key, size_t klen)
{
    size_t cap;
    void *m;

    if(j->n == j->cap)
    {
        cap = j->cap ? j->cap * 2 : 4;
        dbg_err_if((m = u_realloc(j->items, cap * sizeof *j->items)) == NULL);
        j->items = m;
        if(j->type == JSON_OBJECT)
        {
            dbg_err_if((m = u_realloc(j->keys, cap * sizeof *j->keys)) == NULL);
            j->keys = m;
            dbg_err_if((m = u_realloc(j->klens, cap * sizeof *j->klens))
                    == NULL);
            j->klens = m;
        }
        j->cap = cap;
    }
    j->items[j->n] = item;
    if(j->type == JSON_OBJECT)
    {
        j->keys[j->n] = key;
        j->klens[j->n] = klen;
    }
    j->n++;

    return 0;
err:
    return ~0;
}

static int json_hex4(json_parser_t *ps, unsigned long *v)
{
    int i, c;

    if(ps->end - ps->p < 4)
        return ~0;
    for(*v = 0, i = 0; i < 4; ++i)
    {
        c = ps->p[i];
        *v <<= 4;
        if(c >= '0' && c <= '9')
            *v |= (unsigned long) (c - '0');
        else if(c >= 'a' && c <= 'f')
            *v |= (unsigned long) (c - 'a' + 10);
        else if(c >= 'A' && c <= 'F')
            *v |= (unsigned long) (c - 'A' + 10);
        else
            return ~0;
    }
    ps->p += 4;
    return 0;
}

static size_t json_put_utf8(char *d, unsigned long cp)
{
    if(cp < 0x80)
        return d[0] = (char) cp, 1;
    if(cp < 0x800)
        return d[0] = (char) (0xC0 | (cp >> 6)),
               d[1] = (char) (0x80 | (cp & 0x3F)), 2;
    if(cp < 0x10000)
        return d[0] = (char) (0xE0 | (cp >> 12)),
               d[1] = (char) (0x80 | ((cp >> 6) & 0x3F)),
               d[2] = (char) (0x80 | (cp & 0x3F)), 3;
    return d[0] = (char) (0xF0 | (cp >> 18)),
           d[1] = (char) (0x80 | ((cp >> 12) & 0x3F)),
           d[2] = (char) (0x80 | ((cp >> 6) & 0x3F)),
           d[3] = (char) (0x80 | (cp & 0x3F)), 4;
}

/* a string at ps->p ('"'): its value in *pout (to free), length *plen */
static int json_parse_string(json_parser_t *ps, char **pout, size_t *plen)
{
    const unsigned char *q;
    unsigned long cp, lo;
    size_t n, cap;
    char *out = NULL;

    ps->p++;    /* '"' */

    /* the decoded string is never longer than the source */
    for(q = ps->p; q < ps->end && *q != '"'; ++q)
        if(*q == '\\' && q + 1 < ps->end)
            ++q;
    cap = (size_t) (q - ps->p) + 1;
    if((out = u_malloc(cap)) == NULL)
        return json_fail(ps, "out of memory"), ~0;

    for(n = 0;;)
    {
        if(ps->p >= ps->end)
        {
            json_fail(ps, "unterminated string");
            goto err;
        }
        if(*ps->p == '"')
        {
            ps->p++;
            break;
        }
        if(*ps->p < 0x20)
        {
            json_fail(ps, "control character in string");
            goto err;
        }
        if(*ps->p != '\\')
        {
            size_t k = json_utf8(ps->p, (size_t) (ps->end - ps->p), &cp);

            if(k == 0)
            {
                json_fail(ps, "invalid UTF-8");
                goto err;
            }
            memcpy(out + n, ps->p, k);
            n += k;
            ps->p += k;
            continue;
        }

        ps->p++;    /* '\' */
        if(ps->p >= ps->end)
        {
            json_fail(ps, "unterminated string");
            goto err;
        }
        switch(*ps->p++)
        {
        case '"':  out[n++] = '"';  break;
        case '\\': out[n++] = '\\'; break;
        case '/':  out[n++] = '/';  break;
        case 'b':  out[n++] = '\b'; break;
        case 'f':  out[n++] = '\f'; break;
        case 'n':  out[n++] = '\n'; break;
        case 'r':  out[n++] = '\r'; break;
        case 't':  out[n++] = '\t'; break;
        case 'u':
            if(json_hex4(ps, &cp))
            {
                json_fail(ps, "bad \\u escape");
                goto err;
            }
            if(cp >= 0xD800 && cp <= 0xDBFF)
            {   /* a surrogate pair: "😀" */
                if(ps->end - ps->p < 6 || ps->p[0] != '\\' || ps->p[1] != 'u')
                {
                    json_fail(ps, "unpaired surrogate");
                    goto err;
                }
                ps->p += 2;
                if(json_hex4(ps, &lo) || lo < 0xDC00 || lo > 0xDFFF)
                {
                    json_fail(ps, "unpaired surrogate");
                    goto err;
                }
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else if(cp >= 0xDC00 && cp <= 0xDFFF) {
                json_fail(ps, "unpaired surrogate");
                goto err;
            }
            /* a \u escape is 6 or 12 source bytes for at most 4 out */
            n += json_put_utf8(out + n, cp);
            break;
        default:
            json_fail(ps, "bad escape");
            goto err;
        }
    }

    out[n] = '\0';
    *pout = out;
    *plen = n;
    return 0;
err:
    U_FREE(out);
    return ~0;
}

static json_t *json_parse_value(json_parser_t *ps, int depth);

static json_t *json_parse_number(json_parser_t *ps)
{
    const unsigned char *s = ps->p;
    char buf[512], *e;
    int frac = 0;
    size_t len;
    json_t *j;

    if(ps->p < ps->end && *ps->p == '-')
        ps->p++;
    if(ps->p < ps->end && *ps->p == '0')
        ps->p++;
    else if(ps->p < ps->end && *ps->p >= '1' && *ps->p <= '9')
        while(ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9')
            ps->p++;
    else
        return json_fail(ps, "bad number"), NULL;
    if(ps->p < ps->end && *ps->p == '.')
    {
        frac = 1;
        if(++ps->p >= ps->end || *ps->p < '0' || *ps->p > '9')
            return json_fail(ps, "bad number"), NULL;
        while(ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9')
            ps->p++;
    }
    if(ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E'))
    {
        frac = 1;
        if(++ps->p < ps->end && (*ps->p == '+' || *ps->p == '-'))
            ps->p++;
        if(ps->p >= ps->end || *ps->p < '0' || *ps->p > '9')
            return json_fail(ps, "bad number"), NULL;
        while(ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9')
            ps->p++;
    }

    if((len = (size_t) (ps->p - s)) >= sizeof buf)
        return json_fail(ps, "number too long"), NULL;
    memcpy(buf, s, len);
    buf[len] = '\0';

    if((j = json_new(JSON_NUMBER)) == NULL)
        return json_fail(ps, "out of memory"), NULL;
    j->num = strtod(buf, &e);
    if(!frac)
    {
        errno = 0;
        j->ival = strtoll(buf, &e, 10);
        /* "-0" is the double -0.0 (as an integer it would lose its sign,
           and -0.0 written back would read differently) */
        j->is_int = (errno == 0) && !(j->ival == 0 && buf[0] == '-');
    }
    if(!isfinite(j->num))
    {
        json_free(j);
        return json_fail(ps, "number out of range"), NULL;
    }

    return j;
}

static json_t *json_parse_literal(json_parser_t *ps, const char *word,
        json_type_t type)
{
    size_t n = strlen(word);

    if((size_t) (ps->end - ps->p) < n || memcmp(ps->p, word, n))
        return json_fail(ps, "unexpected character"), NULL;
    ps->p += n;

    return json_new(type);
}

static json_t *json_parse_array(json_parser_t *ps, int depth)
{
    json_t *j, *item;

    ps->p++;    /* '[' */
    if((j = json_new(JSON_ARRAY)) == NULL)
        return json_fail(ps, "out of memory"), NULL;

    json_ws(ps);
    if(ps->p < ps->end && *ps->p == ']')
    {
        ps->p++;
        return j;
    }
    for(;;)
    {
        if((item = json_parse_value(ps, depth + 1)) == NULL)
            goto err;
        if(json_push(j, item, NULL, 0))
        {
            json_free(item);
            json_fail(ps, "out of memory");
            goto err;
        }
        json_ws(ps);
        if(ps->p < ps->end && *ps->p == ',')
        {
            ps->p++;
            continue;
        }
        if(ps->p < ps->end && *ps->p == ']')
        {
            ps->p++;
            return j;
        }
        json_fail(ps, "expected ',' or ']'");
        goto err;
    }
err:
    json_free(j);
    return NULL;
}

static json_t *json_parse_object(json_parser_t *ps, int depth)
{
    json_t *j, *item;
    char *key = NULL;
    size_t klen, i;

    ps->p++;    /* '{' */
    if((j = json_new(JSON_OBJECT)) == NULL)
        return json_fail(ps, "out of memory"), NULL;

    json_ws(ps);
    if(ps->p < ps->end && *ps->p == '}')
    {
        ps->p++;
        return j;
    }
    for(;;)
    {
        json_ws(ps);
        if(ps->p >= ps->end || *ps->p != '"')
        {
            json_fail(ps, "expected a key");
            goto err;
        }
        if(json_parse_string(ps, &key, &klen))
            goto err;
        for(i = 0; i < j->n; ++i)
            if(j->klens[i] == klen && !memcmp(j->keys[i], key, klen))
            {
                json_fail(ps, "duplicate key");
                goto err;
            }
        json_ws(ps);
        if(ps->p >= ps->end || *ps->p != ':')
        {
            json_fail(ps, "expected ':'");
            goto err;
        }
        ps->p++;
        if((item = json_parse_value(ps, depth + 1)) == NULL)
            goto err;
        if(json_push(j, item, key, klen))
        {
            json_free(item);
            json_fail(ps, "out of memory");
            goto err;
        }
        key = NULL;
        json_ws(ps);
        if(ps->p < ps->end && *ps->p == ',')
        {
            ps->p++;
            continue;
        }
        if(ps->p < ps->end && *ps->p == '}')
        {
            ps->p++;
            return j;
        }
        json_fail(ps, "expected ',' or '}'");
        goto err;
    }
err:
    U_FREE(key);
    json_free(j);
    return NULL;
}

static json_t *json_parse_value(json_parser_t *ps, int depth)
{
    json_t *j;

    if(depth > JSON_MAX_DEPTH)
        return json_fail(ps, "nested too deep"), NULL;

    json_ws(ps);
    if(ps->p >= ps->end)
        return json_fail(ps, "unexpected end"), NULL;

    switch(*ps->p)
    {
    case '{':
        return json_parse_object(ps, depth);
    case '[':
        return json_parse_array(ps, depth);
    case '"':
        if((j = json_new(JSON_STRING)) == NULL)
            return json_fail(ps, "out of memory"), NULL;
        if(json_parse_string(ps, &j->str, &j->slen))
        {
            json_free(j);
            return NULL;
        }
        return j;
    case 't':
        return json_parse_literal(ps, "true", JSON_TRUE);
    case 'f':
        return json_parse_literal(ps, "false", JSON_FALSE);
    case 'n':
        return json_parse_literal(ps, "null", JSON_NULL);
    default:
        return json_parse_number(ps);
    }
}

/**
 * \brief   Parse a JSON text
 *
 * \param text   the text (need not be NUL-terminated)
 * \param len    its length
 * \param pj     the document, to free with json_free()
 * \param err    where to write what went wrong (may be NULL)
 * \param errsz  its size
 *
 * \return \c 0 if the whole text is one valid JSON value, \c ~0 otherwise
 */
int json_parse(const char *text, size_t len, json_t **pj, char *err,
        size_t errsz)
{
    json_parser_t ps;
    json_t *j;

    dbg_return_if (text == NULL || pj == NULL, ~0);

    memset(&ps, 0, sizeof ps);
    ps.p = ps.start = (const unsigned char *) text;
    ps.end = ps.p + len;
    ps.err = err;
    ps.errsz = errsz;
    if(err && errsz)
        err[0] = '\0';

    if((j = json_parse_value(&ps, 1)) == NULL)
        return ~0;

    json_ws(&ps);
    if(ps.p != ps.end)
    {
        json_fail(&ps, "text after the value");
        json_free(j);
        return ~0;
    }

    *pj = j;
    return 0;
}

void json_free(json_t *j)
{
    size_t i;

    if(j == NULL)
        return;
    for(i = 0; i < j->n; ++i)
    {
        json_free(j->items[i]);
        if(j->keys)
            U_FREE(j->keys[i]);
    }
    U_FREE(j->items);
    U_FREE(j->keys);
    U_FREE(j->klens);
    U_FREE(j->str);
    u_free(j);
}

/* ------------------------------------------------------------------------
 * accessors (all accept NULL, so lookups can be chained)
 * ---------------------------------------------------------------------- */

json_type_t json_type(const json_t *j)
{
    return j ? j->type : JSON_NULL;
}

/* the member 'key' of an object, or NULL */
json_t *json_get(const json_t *obj, const char *key)
{
    size_t i, klen;

    if(obj == NULL || obj->type != JSON_OBJECT || key == NULL)
        return NULL;
    klen = strlen(key);
    for(i = 0; i < obj->n; ++i)
        if(obj->klens[i] == klen && !memcmp(obj->keys[i], key, klen))
            return obj->items[i];
    return NULL;
}

/* item i of an array, or member i of an object */
json_t *json_at(const json_t *j, size_t i)
{
    if(j == NULL || (j->type != JSON_ARRAY && j->type != JSON_OBJECT) ||
            i >= j->n)
        return NULL;
    return j->items[i];
}

const char *json_key_at(const json_t *obj, size_t i)
{
    if(obj == NULL || obj->type != JSON_OBJECT || i >= obj->n)
        return NULL;
    return obj->keys[i];
}

/* items of an array or members of an object (0 otherwise) */
size_t json_count(const json_t *j)
{
    return (j && (j->type == JSON_ARRAY || j->type == JSON_OBJECT)) ? j->n : 0;
}

/* a string's value, or NULL if j is not a string */
const char *json_string(const json_t *j)
{
    return (j && j->type == JSON_STRING) ? j->str : NULL;
}

size_t json_string_len(const json_t *j)
{
    return (j && j->type == JSON_STRING) ? j->slen : 0;
}

/* a number's value (0 if j is not a number) */
double json_number(const json_t *j)
{
    return (j && j->type == JSON_NUMBER) ? j->num : 0;
}

/* an integer that fits int64_t exactly: 0 and *pv, ~0 otherwise (not a
 * number, a fraction or exponent form, or out of range) */
int json_int64(const json_t *j, int64_t *pv)
{
    if(j == NULL || j->type != JSON_NUMBER || !j->is_int || pv == NULL)
        return ~0;
    *pv = j->ival;
    return 0;
}

/* 1 for true, 0 otherwise */
int json_bool(const json_t *j)
{
    return j && j->type == JSON_TRUE;
}

/* ------------------------------------------------------------------------
 * writer
 * ---------------------------------------------------------------------- */

struct json_writer_s
{
    io_t *out;
    int failed;
    int depth;
    char kind[JSON_MAX_DEPTH + 1];  /* 'a' array or 'o' object per level */
    size_t count[JSON_MAX_DEPTH + 1];
    int after_key;                  /* an object key wants its value      */
    int done;                       /* the top value has been written     */
};

int json_writer_create(io_t *out, json_writer_t **pw)
{
    json_writer_t *w;

    dbg_return_if (out == NULL || pw == NULL, ~0);
    dbg_return_if ((w = u_zalloc(sizeof *w)) == NULL, ~0);

    w->out = out;
    *pw = w;

    return 0;
}

/* free the writer: 0 if one complete document was written without error */
int json_writer_free(json_writer_t *w)
{
    int rc;

    if(w == NULL)
        return ~0;
    rc = (w->failed || w->depth || !w->done) ? ~0 : 0;
    u_free(w);

    return rc;
}

static int json_put(json_writer_t *w, const char *s, size_t n)
{
    if(!w->failed && n && io_write(w->out, s, n) < (ssize_t) n)
        w->failed = 1;
    return w->failed ? ~0 : 0;
}

/* before a value: the separator, and a check that a value may go here */
static int json_pre_value(json_writer_t *w)
{
    if(w->failed)
        return ~0;
    if(w->depth == 0)
    {
        if(w->done)
            return w->failed = 1, ~0;   /* one document per writer */
        return 0;
    }
    if(w->kind[w->depth] == 'o')
    {
        if(!w->after_key)
            return w->failed = 1, ~0;   /* a value needs a key here */
        w->after_key = 0;
        return 0;
    }
    if(w->count[w->depth]++)
        return json_put(w, ",", 1);
    return 0;
}

static void json_post_value(json_writer_t *w)
{
    if(w->depth == 0)
        w->done = 1;
}

/* write s as a JSON string: quotes, backslashes and control characters
 * escaped, and also < > & and U+2028/U+2029, so the text can go inside an
 * HTML <script>; invalid UTF-8 becomes U+FFFD */
static int json_put_string(json_writer_t *w, const char *s, size_t len)
{
    const unsigned char *p = (const unsigned char *) s, *e = p + len;
    char esc[8];
    unsigned long cp;
    size_t k;

    json_put(w, "\"", 1);
    while(p < e)
    {
        if((k = json_utf8(p, (size_t) (e - p), &cp)) == 0)
        {
            json_put(w, "\\ufffd", 6);
            p++;
            continue;
        }
        if(cp == '"' || cp == '\\')
        {
            esc[0] = '\\';
            esc[1] = (char) cp;
            json_put(w, esc, 2);
        } else if(cp == '\n')
            json_put(w, "\\n", 2);
        else if(cp == '\r')
            json_put(w, "\\r", 2);
        else if(cp == '\t')
            json_put(w, "\\t", 2);
        else if(cp < 0x20 || cp == '<' || cp == '>' || cp == '&' ||
                cp == 0x2028 || cp == 0x2029)
        {
            (void) snprintf(esc, sizeof esc, "\\u%04lx", cp);
            json_put(w, esc, 6);
        } else
            json_put(w, (const char *) p, k);
        p += k;
    }
    return json_put(w, "\"", 1);
}

static int json_begin(json_writer_t *w, char kind)
{
    if(json_pre_value(w))
        return ~0;
    if(w->depth == JSON_MAX_DEPTH)
        return w->failed = 1, ~0;
    w->depth++;
    w->kind[w->depth] = kind;
    w->count[w->depth] = 0;
    return json_put(w, kind == 'o' ? "{" : "[", 1);
}

static int json_end(json_writer_t *w, char kind)
{
    if(w->failed || w->depth == 0 || w->kind[w->depth] != kind ||
            w->after_key)
        return w->failed = 1, ~0;
    w->depth--;
    if(json_put(w, kind == 'o' ? "}" : "]", 1))
        return ~0;
    json_post_value(w);
    return 0;
}

int json_begin_object(json_writer_t *w) { return json_begin(w, 'o'); }
int json_end_object(json_writer_t *w)   { return json_end(w, 'o'); }
int json_begin_array(json_writer_t *w)  { return json_begin(w, 'a'); }
int json_end_array(json_writer_t *w)    { return json_end(w, 'a'); }

/* the key (len bytes, which may hold NULs) of the next member of the
 * current object */
int json_keyn(json_writer_t *w, const char *key, size_t len)
{
    dbg_return_if (w == NULL || key == NULL, ~0);

    if(w->failed || w->depth == 0 || w->kind[w->depth] != 'o' || w->after_key)
        return w->failed = 1, ~0;
    if(w->count[w->depth]++)
        json_put(w, ",", 1);
    json_put_string(w, key, len);
    w->after_key = 1;
    return json_put(w, ":", 1);
}

int json_key(json_writer_t *w, const char *key)
{
    return json_keyn(w, key, key ? strlen(key) : 0);
}

int json_strn(json_writer_t *w, const char *s, size_t len)
{
    dbg_return_if (w == NULL, ~0);

    if(s == NULL)
        return json_null(w);
    if(json_pre_value(w) || json_put_string(w, s, len))
        return ~0;
    json_post_value(w);
    return 0;
}

int json_str(json_writer_t *w, const char *s)
{
    return json_strn(w, s, s ? strlen(s) : 0);
}

static int json_raw_value(json_writer_t *w, const char *s)
{
    dbg_return_if (w == NULL, ~0);

    if(json_pre_value(w) || json_put(w, s, strlen(s)))
        return ~0;
    json_post_value(w);
    return 0;
}

int json_int(json_writer_t *w, int64_t v)
{
    char buf[32];

    (void) snprintf(buf, sizeof buf, "%lld", (long long) v);
    return json_raw_value(w, buf);
}

/* a double; NaN and infinities have no JSON form and fail */
int json_double(json_writer_t *w, double v)
{
    char buf[40];

    if(!isfinite(v))
        return w ? (w->failed = 1, ~0) : ~0;
    (void) snprintf(buf, sizeof buf, "%.17g", v);
    return json_raw_value(w, buf);
}

int json_boolean(json_writer_t *w, int b)
{
    return json_raw_value(w, b ? "true" : "false");
}

int json_null(json_writer_t *w)
{
    return json_raw_value(w, "null");
}

/* write a parsed value (a whole tree) */
int json_value(json_writer_t *w, const json_t *j)
{
    size_t i;

    dbg_return_if (w == NULL, ~0);

    switch(json_type(j))
    {
    case JSON_NULL:   return json_null(w);
    case JSON_TRUE:   return json_boolean(w, 1);
    case JSON_FALSE:  return json_boolean(w, 0);
    case JSON_STRING: return json_strn(w, j->str, j->slen);
    case JSON_NUMBER:
        return j->is_int ? json_int(w, j->ival) : json_double(w, j->num);
    case JSON_ARRAY:
        if(json_begin_array(w))
            return ~0;
        for(i = 0; i < j->n; ++i)
            if(json_value(w, j->items[i]))
                return ~0;
        return json_end_array(w);
    case JSON_OBJECT:
        if(json_begin_object(w))
            return ~0;
        for(i = 0; i < j->n; ++i)
            if(json_keyn(w, j->keys[i], j->klens[i]) ||
                    json_value(w, j->items[i]))
                return ~0;
        return json_end_object(w);
    }
    return ~0;
}
