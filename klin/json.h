/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_JSON_H_
#define _KLIN_JSON_H_

#include <stddef.h>
#include <stdint.h>
#include <klin/io.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A small JSON (RFC 8259) reader and writer, see doc/JSON.
 *
 * Reading builds a tree:
 *
 *     json_t *doc;
 *     if(json_parse(text, len, &doc, err, sizeof err) == 0)
 *     {
 *         const char *name = json_string(json_get(doc, "name"));
 *         json_free(doc);
 *     }
 *
 * Writing streams to an io_t (a page's "out"):
 *
 *     json_writer_t *w;
 *     json_writer_create(out, &w);
 *     json_begin_object(w);
 *     json_key(w, "id");   json_int(w, 42);
 *     json_key(w, "tags"); json_begin_array(w); json_str(w, "a");
 *     json_end_array(w);
 *     json_end_object(w);
 *     json_writer_free(w);           (0 if the document was complete)
 */

typedef enum {
    JSON_NULL, JSON_FALSE, JSON_TRUE, JSON_NUMBER, JSON_STRING, JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

enum {
    JSON_MAX_DEPTH = 64         /* deepest nesting json_parse() accepts      */
};

struct json_s;
typedef struct json_s json_t;

int json_parse(const char *text, size_t len, json_t **pj, char *err,
        size_t errsz);
void json_free(json_t *j);

json_type_t json_type(const json_t *j);
json_t *json_get(const json_t *obj, const char *key);
json_t *json_at(const json_t *arr, size_t i);
size_t json_count(const json_t *j);
const char *json_key_at(const json_t *obj, size_t i);
const char *json_string(const json_t *j);
size_t json_string_len(const json_t *j);
double json_number(const json_t *j);
int json_int64(const json_t *j, int64_t *pv);
int json_bool(const json_t *j);

struct json_writer_s;
typedef struct json_writer_s json_writer_t;

int json_writer_create(io_t *out, json_writer_t **pw);
int json_writer_free(json_writer_t *w);
int json_begin_object(json_writer_t *w);
int json_end_object(json_writer_t *w);
int json_begin_array(json_writer_t *w);
int json_end_array(json_writer_t *w);
int json_key(json_writer_t *w, const char *key);
int json_keyn(json_writer_t *w, const char *key, size_t len);
int json_str(json_writer_t *w, const char *s);
int json_strn(json_writer_t *w, const char *s, size_t len);
int json_int(json_writer_t *w, int64_t v);
int json_double(json_writer_t *w, double v);
int json_boolean(json_writer_t *w, int b);
int json_null(json_writer_t *w);
int json_value(json_writer_t *w, const json_t *j);

#ifdef __cplusplus
}
#endif

#endif
