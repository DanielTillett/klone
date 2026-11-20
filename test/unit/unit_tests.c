/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject
 * to the license stated in the LICENSE file which you have received as part
 * of this distribution.
 */

/* Unit tests linked against the real Klin libraries (CTest: "unit"). Unlike
 * test/regressions.c, nothing is stubbed: header parsing runs on the real
 * buffered io, the translator on real parser input, the timer. */

#include "klin_conf.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <u/libu.h>
#include <klin/field.h>
#include <klin/header.h>
#include <klin/io.h>
#include <klin/timer.h>
#include <klin/translat.h>
#include <klin/json.h>
#include <klin/utils.h>
#include <math.h>
#include <klin/crypto.h>
#ifdef SSL_OPENSSL
#include <klin/auth.h>
#endif

/* the syslog facility LibU logs with: the program defines it */
int facility = LOG_LOCAL0;

static int checks, failures;

#define CHECK(expr) do {                                                    \
        ++checks;                                                           \
        if(!(expr)) {                                                       \
            ++failures;                                                     \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__,         \
                    __LINE__, #expr);                                       \
        }                                                                   \
    } while(0)

/* load 'text' into a new header with header_load_ex(); return its result */
static int load(const char *text, size_t len, header_t **ph)
{
    io_t *io = NULL;
    int rc;

    if(io_mem_create((char *) text, len, 0, &io) || header_create(ph))
        return ~0;
    rc = header_load_ex(*ph, io, HLM_ADD);
    io_free(io);
    return rc;
}

static void test_header_fields(void)
{
    static const char text[] = "Host: x\r\nCookie: a=1\r\nConnection: "
        "keep-alive, Close\r\nCookie: b=2\r\n\r\n";
    header_t *h = NULL;
    field_t *f;
    int n = 0;

    CHECK(load(text, strlen(text), &h) == 0);
    CHECK(header_field_count(h) == 4);
    CHECK(header_count_field(h, "cookie") == 2);
    CHECK(header_count_field(h, "missing") == 0);

    /* header_next_field: by name, in order; all fields with NULL */
    f = header_next_field(h, "COOKIE", NULL);
    CHECK(f && !strcmp(field_get_value(f), "a=1"));
    f = header_next_field(h, "cookie", f);
    CHECK(f && !strcmp(field_get_value(f), "b=2"));
    CHECK(header_next_field(h, "cookie", f) == NULL);
    for(f = NULL; (f = header_next_field(h, NULL, f)) != NULL; )
        ++n;
    CHECK(n == 4);

    /* header_get_fieldn resumes from its cursor, also backwards */
    CHECK(!strcmp(field_get_name(header_get_fieldn(h, 3)), "Cookie"));
    CHECK(!strcmp(field_get_name(header_get_fieldn(h, 0)), "Host"));
    CHECK(header_get_fieldn(h, 4) == NULL);

    CHECK(header_has_token(h, "connection", "close"));
    CHECK(!header_has_token(h, "connection", "upgrade"));
    header_free(h);
}

/* "X: aaa...\r\n" lines of 'len' bytes (with the CRLF), 'n' of them, then
   the empty line */
static char *make_lines(size_t len, size_t n, size_t *plen)
{
    size_t i, total = len * n + 2;
    char *buf = malloc(total), *p = buf;

    for(i = 0; i < n; ++i, p += len)
    {
        memset(p, 'a', len);
        memcpy(p, "X: ", 3);
        memcpy(p + len - 2, "\r\n", 2);
    }
    memcpy(p, "\r\n", 2);
    *plen = total;
    return buf;
}

static void test_header_limits(void)
{
    header_t *h;
    size_t len;
    char *buf;

    /* lines longer than the io buffer (4 KB), read across refills: 8192
       bytes with the LF is the longest accepted */
    buf = make_lines(8192, 1, &len);
    h = NULL;
    CHECK(load(buf, len, &h) == 0 && header_field_count(h) == 1 &&
            strlen(field_get_value(header_get_fieldn(h, 0))) == 8192 - 5);
    header_free(h);
    free(buf);

    buf = make_lines(8193, 1, &len);
    h = NULL;
    CHECK(load(buf, len, &h) != 0);
    header_free(h);
    free(buf);

    /* at most 256 fields */
    buf = make_lines(10, 256, &len);
    h = NULL;
    CHECK(load(buf, len, &h) == 0 && header_field_count(h) == 256);
    header_free(h);
    free(buf);

    buf = make_lines(10, 257, &len);
    h = NULL;
    CHECK(load(buf, len, &h) != 0);
    header_free(h);
    free(buf);

    /* at most 64 KB in all */
    buf = make_lines(8000, 9, &len);
    h = NULL;
    CHECK(load(buf, len, &h) != 0);
    header_free(h);
    free(buf);

    /* a header cut short (no empty line) is an error */
    h = NULL;
    CHECK(load("X: 1\r\n", 6, &h) != 0);
    header_free(h);
}

static void test_field_reuse(void)
{
    char longer[300];
    field_t *f = NULL, *g = NULL;

    CHECK(field_create("Name", "short", &f) == 0);

    /* new values taken from the field's own buffer */
    CHECK(field_set(f, field_get_name(f), field_get_name(f)) == 0);
    CHECK(!strcmp(field_get_name(f), "Name") &&
            !strcmp(field_get_value(f), "Name"));

    /* a value that does not fit the buffer */
    memset(longer, 'v', sizeof longer - 1);
    longer[sizeof longer - 1] = '\0';
    CHECK(field_set(f, "Name", longer) == 0);
    CHECK(!strcmp(field_get_value(f), longer));
    CHECK(field_set(f, "Other", field_get_value(f) + 290) == 0);
    CHECK(!strcmp(field_get_name(f), "Other") &&
            !strcmp(field_get_value(f), "vvvvvvvvv"));
    field_free(f);

    /* freed fields are reused: the next one must start clean */
    CHECK(field_create("A", "1", &f) == 0);
    field_free(f);
    CHECK(field_create(NULL, NULL, &g) == 0);
    CHECK(field_get_name(g) == NULL && field_get_value(g) == NULL);
    field_free(g);
}

static int fired;

static int on_alarm(talarm_t *al, void *arg)
{
    (void) al;
    fired = *(int *) arg;
    return 0;
}

/* an alarm that closes the descriptor being waited for (as a timeout does) */
static int on_close(talarm_t *al, void *arg)
{
    int *pfd = arg;

    (void) al;
    close(*pfd);
    *pfd = -1;
    return 0;
}

static void test_timer(void)
{
    talarm_t *a = NULL, *b = NULL, *c = NULL;
    int one = 1, two = 2, p[2];
    time_t t0, dt;

    /* alarms run while waiting: a deleted one never, the others in order,
       the last closing the descriptor, which ends the wait */
    fired = 0;
    CHECK(timerm_add(1, on_alarm, &one, &a) == 0);
    CHECK(timerm_add(2, on_alarm, &two, &b) == 0);
    CHECK(timerm_armed());
    CHECK(timerm_del(a) == 0);      /* the earliest one */
    CHECK(pipe(p) == 0);
    CHECK(timerm_add(3, on_close, &p[0], &c) == 0);
    t0 = time(NULL);
    CHECK(timerm_wait(&p[0], TIMERM_WAIT_READ) != 0);
    dt = time(NULL) - t0;
    CHECK(p[0] == -1 && fired == 2);
    CHECK(dt >= 2 && dt <= 5);
    CHECK(!timerm_armed());
    CHECK(timerm_del(b) == 0);      /* fired: off the list, still freed here */
    CHECK(timerm_del(c) == 0);
    close(p[1]);

    /* a ready descriptor does not wait for the alarm, which stays set */
    fired = 0;
    CHECK(pipe(p) == 0);
    CHECK(write(p[1], "x", 1) == 1);
    CHECK(timerm_add(5, on_alarm, &one, &a) == 0);
    t0 = time(NULL);
    CHECK(timerm_wait(&p[0], TIMERM_WAIT_READ) == 0);
    CHECK(time(NULL) - t0 <= 1 && fired == 0);
    CHECK(timerm_armed());
    CHECK(timerm_del(a) == 0);
    CHECK(!timerm_armed() && timerm_run() == -1);
    close(p[0]);
    close(p[1]);
}

/* translate 'page' as 'uri'; return the generated C (to free) or NULL */
static char *translate_page(const char *page, const char *uri)
{
    char path[] = "/tmp/klin-unit-XXXXXX", *c = NULL;
    trans_info_t ti;
    io_t *in = NULL, *out = NULL;
    FILE *fp;
    long sz;
    int fd;

    memset(&ti, 0, sizeof ti);
    (void) u_strlcpy(ti.uri, uri, sizeof ti.uri);
    (void) u_strlcpy(ti.file_in, "page.kl1", sizeof ti.file_in);

    if((fd = mkstemp(path)) < 0)
        return NULL;
    if(io_mem_create((char *) page, strlen(page), 0, &in) ||
            io_fd_create(fd, IO_FD_CLOSE, &out) ||
            translate_script_to_c(in, out, &ti))
        goto end;
    io_free(out);
    out = NULL;

    if((fp = fopen(path, "rb")) != NULL)
    {
        fseek(fp, 0, SEEK_END);
        sz = ftell(fp);
        rewind(fp);
        if(sz > 0 && (c = calloc(1, (size_t) sz + 1)) != NULL &&
                fread(c, 1, (size_t) sz, fp) != (size_t) sz)
        {
            free(c);
            c = NULL;
        }
        fclose(fp);
    }
end:
    if(in)
        io_free(in);
    if(out)
        io_free(out);
    unlink(path);
    return c;
}

static void test_translate(void)
{
    char *c;

    c = translate_page("<b><%= \"x\" %></b><% int i = 1; (void) i; %>"
            "<%! static int helper; %>\n", "/dir/page.kl1");
    CHECK(c != NULL);
    if(c)
    {
        CHECK(strstr(c, "SCRIPT_NAME = \"page.kl1\";") != NULL);
        /* <%= expr %> prints the expression (spacing is the parser's) */
        CHECK(strstr(c, "io_printf(out, \"%s\",") != NULL &&
                strstr(strstr(c, "io_printf(out, \"%s\","), "\"x\"") != NULL);
        CHECK(strstr(c, "int i = 1; (void) i;") != NULL);
        CHECK(strstr(c, "static int helper;") != NULL);
        CHECK(strstr(c, "e.res.filename = \"/dir/page.kl1\";") != NULL);
        free(c);
    }

    /* a URI is written as an escaped C string literal ("?\?=": a trigraph
       in this source otherwise) */
    c = translate_page("<p>", "/a\"b\\c?\?=\001.kl1");
    CHECK(c != NULL);
    if(c)
    {
        CHECK(strstr(c, "SCRIPT_NAME = \"a\\\"b\\\\c\\?\\?=\\001.kl1\";")
                != NULL);
        free(c);
    }
}

#ifdef SSL_OPENSSL
/* HTTP authentication hashes: the RFC 7616 3.9.1 examples, and PBKDF2
   password hashes */
static void test_auth(void)
{
    static const char nonce[] = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
        cnonce[] = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
    char ha1[AUTH_HEX_SZ], r[AUTH_HEX_SZ], stored[AUTH_PASSWORD_SZ],
         other[AUTH_PASSWORD_SZ];

    CHECK(auth_digest_ha1(AUTH_ALG_SHA256, "Mufasa", "http-auth@example.org",
                "Circle of Life", ha1) == 0);
    CHECK(!strcmp(ha1, "7987c64c30e25f1b74be53f966b49b90"
                "f2808aa92faf9a00262392d7b4794232"));
    CHECK(auth_digest_response(AUTH_ALG_SHA256, ha1, nonce, "00000001",
                cnonce, "GET", "/dir/index.html", r) == 0);
    CHECK(!strcmp(r, "753927fa0e85d155564e2e272a28d180"
                "2ca10daf4496794697cf8db5856cb6c1"));

    CHECK(auth_digest_ha1(AUTH_ALG_MD5, "Mufasa", "http-auth@example.org",
                "Circle of Life", ha1) == 0);
    CHECK(auth_digest_response(AUTH_ALG_MD5, ha1, nonce, "00000001",
                cnonce, "GET", "/dir/index.html", r) == 0);
    CHECK(!strcmp(r, "8ca523f5e9506fed4657c9700eebdbec"));

    CHECK(auth_alg_from_name("sha-256") == AUTH_ALG_SHA256);
    CHECK(auth_alg_from_name("MD5") == AUTH_ALG_MD5);
    CHECK(auth_alg_from_name("SHA-512-256") == 0);
    CHECK(auth_alg_from_name(NULL) == 0);

    /* salted: the same password hashes differently, both verify */
    CHECK(auth_password_hash("s3cret pw", 1000, stored, sizeof stored) == 0);
    CHECK(auth_password_hash("s3cret pw", 1000, other, sizeof other) == 0);
    CHECK(!strncmp(stored, "pbkdf2-sha256$1000$", 19));
    CHECK(strcmp(stored, other) != 0);
    CHECK(auth_password_verify("s3cret pw", stored) == 0);
    CHECK(auth_password_verify("s3cret pw", other) == 0);
    CHECK(auth_password_verify("s3cret pX", stored) != 0);
    CHECK(auth_password_verify("", stored) != 0);

    /* malformed stored values never verify (and plaintext is not a hash) */
    CHECK(auth_password_verify("s3cret pw", "s3cret pw") != 0);
    CHECK(auth_password_verify("x", "pbkdf2-sha256$0$AAAA$AAAA") != 0);
    CHECK(auth_password_verify("x", "pbkdf2-sha256$10$AAAA") != 0);
    CHECK(auth_password_verify("x", "pbkdf2-sha256$x$$") != 0);
    stored[strlen(stored) - 3] ^= 1;    /* a changed hash */
    CHECK(auth_password_verify("s3cret pw", stored) != 0);

    /* a hash that does not fit the buffer is an error */
    CHECK(auth_password_hash("pw", 1000, stored, 20) != 0);
}
#endif

/* parse 'text': 0 if valid (then *pj is set), ~0 if refused */
static int parse(const char *text, json_t **pj)
{
    char err[128];

    return json_parse(text, strlen(text), pj, err, sizeof err);
}

static int refused(const char *text)
{
    json_t *j = NULL;
    int rc = parse(text, &j);

    json_free(j);
    return rc != 0;
}

static void test_json_parse(void)
{
    static const char doc[] = " {\"name\": \"Klin\", \"n\": -12, \"pi\": 3.25e0,"
        " \"big\": 123456789012345678901, \"ok\": true, \"no\": false,"
        " \"none\": null, \"list\": [1, [2, {}], \"x\"],"
        " \"esc\": \"a\\\"b\\\\c\\/d\\n\\u00e9\\u2603\\ud83d\\ude00\" } ";
    json_t *j = NULL, *list;
    char err[128];
    int64_t v;

    CHECK(parse(doc, &j) == 0);
    CHECK(json_type(j) == JSON_OBJECT && json_count(j) == 9);
    CHECK(!strcmp(json_string(json_get(j, "name")), "Klin"));
    CHECK(json_int64(json_get(j, "n"), &v) == 0 && v == -12);
    CHECK(json_number(json_get(j, "pi")) == 3.25);
    CHECK(json_int64(json_get(j, "pi"), &v) != 0);      /* not an integer */
    CHECK(json_int64(json_get(j, "big"), &v) != 0);     /* out of range */
    CHECK(json_number(json_get(j, "big")) > 1e20);
    CHECK(json_bool(json_get(j, "ok")) && !json_bool(json_get(j, "no")));
    CHECK(json_type(json_get(j, "none")) == JSON_NULL &&
            json_get(j, "none") != NULL && json_get(j, "missing") == NULL);
    list = json_get(j, "list");
    CHECK(json_count(list) == 3 && json_count(json_at(list, 1)) == 2);
    CHECK(json_type(json_at(json_at(list, 1), 1)) == JSON_OBJECT);
    CHECK(json_at(list, 3) == NULL && json_string(json_at(list, 0)) == NULL);
    CHECK(!strcmp(json_string(json_get(j, "esc")),
                "a\"b\\c/d\n\xc3\xa9\xe2\x98\x83\xf0\x9f\x98\x80"));
    CHECK(!strcmp(json_key_at(j, 0), "name"));
    /* lookups through missing values are safe */
    CHECK(json_string(json_get(json_get(j, "nope"), "deeper")) == NULL);
    json_free(j);

    /* -0 keeps its sign: a double, not the integer 0 (found by fuzzing:
       -0.0 was written "-0", which read back as 0) */
    CHECK(parse("-0", &j) == 0 && json_int64(j, &v) != 0 &&
            json_number(j) == 0 && signbit(json_number(j)));
    json_free(j);
    CHECK(parse("0", &j) == 0 && json_int64(j, &v) == 0 && v == 0);
    json_free(j);

    CHECK(parse("\"a\\u0000b\"", &j) == 0 && json_string_len(j) == 3);
    json_free(j);
    CHECK(parse("0", &j) == 0 && json_int64(j, &v) == 0 && v == 0);
    json_free(j);
    CHECK(parse("-9223372036854775808", &j) == 0 && json_int64(j, &v) == 0 &&
            v == INT64_MIN);
    json_free(j);

    /* refused */
    CHECK(refused(""));
    CHECK(refused("   "));
    CHECK(refused("[1,]"));
    CHECK(refused("{\"a\":1,}"));
    CHECK(refused("[1 2]"));
    CHECK(refused("{'a':1}"));
    CHECK(refused("{a:1}"));
    CHECK(refused("[1] // comment"));
    CHECK(refused("[1] x"));
    CHECK(refused("01"));
    CHECK(refused("1."));
    CHECK(refused(".5"));
    CHECK(refused("+1"));
    CHECK(refused("1e"));
    CHECK(refused("NaN"));
    CHECK(refused("Infinity"));
    CHECK(refused("1e999"));
    CHECK(refused("tru"));
    CHECK(refused("nul"));
    CHECK(refused("\"tab\there\""));         /* raw control character */
    CHECK(refused("\"\\x41\""));
    CHECK(refused("\"\\u12\""));
    CHECK(refused("\"\\ud83d\""));          /* lone high surrogate */
    CHECK(refused("\"\\ude00\""));          /* lone low surrogate */
    CHECK(refused("\"\\ud83d\\u0041\""));
    CHECK(refused("\"\xc3\x28\""));         /* invalid UTF-8 */
    CHECK(refused("\"\xc0\xaf\""));         /* overlong */
    CHECK(refused("\"\xed\xa0\x80\""));     /* encoded surrogate */
    CHECK(refused("\"open"));
    CHECK(refused("{\"a\":1,\"a\":2}"));    /* duplicate key */
    CHECK(json_parse("[1]", 2, &j, err, sizeof err) != 0);  /* cut short */

    /* depth: JSON_MAX_DEPTH levels are fine, one more is not */
    {
        char deep[2 * JSON_MAX_DEPTH + 3];
        int i;

        for(i = 0; i < JSON_MAX_DEPTH; ++i)
        {
            deep[i] = '[';
            deep[JSON_MAX_DEPTH + i] = ']';
        }
        deep[2 * JSON_MAX_DEPTH] = '\0';
        CHECK(parse(deep, &j) == 0);
        json_free(j);
        memmove(deep + 1, deep, 2 * JSON_MAX_DEPTH + 1);
        deep[0] = '[';
        strcat(deep, "]");
        CHECK(refused(deep));
    }

    /* the error says what and where */
    CHECK(json_parse("[1,]", 4, &j, err, sizeof err) != 0 &&
            strstr(err, "offset 3") != NULL);
}

/* run 'fn' with a writer on a memory buffer: what it wrote, and whether
   the writer called it a complete document */
static char json_out[4096];

static int written(int (*fn)(json_writer_t *))
{
    json_writer_t *w = NULL;
    io_t *io = NULL;
    int rc;

    memset(json_out, 0, sizeof json_out);
    if(io_mem_create(json_out, sizeof json_out - 1, 0, &io) ||
            json_writer_create(io, &w))
        return -1;
    (void) fn(w);
    rc = json_writer_free(w);
    io_flush(io);
    io_free(io);
    return rc;
}

static int write_doc(json_writer_t *w)
{
    json_begin_object(w);
    json_key(w, "id");      json_int(w, -42);
    json_key(w, "name");    json_str(w, "<script>\"x\"&\\\n\xe2\x80\xa8");
    json_key(w, "bad");     json_strn(w, "a\xff" "b", 3);
    json_key(w, "list");    json_begin_array(w);
    json_double(w, 0.5);    json_boolean(w, 1);   json_null(w);
    json_begin_object(w);   json_end_object(w);
    json_end_array(w);
    json_key(w, "ctl");     json_str(w, "\x01");
    return json_end_object(w);
}

static int write_no_key(json_writer_t *w)
{
    json_begin_object(w);
    json_int(w, 1);         /* a value without a key */
    return json_end_object(w);
}

static int write_two(json_writer_t *w)
{
    json_int(w, 1);
    return json_int(w, 2);  /* a second top-level value */
}

static int write_open(json_writer_t *w)
{
    return json_begin_array(w);     /* never closed */
}

static int write_mismatch(json_writer_t *w)
{
    json_begin_array(w);
    return json_end_object(w);
}

static int write_nan(json_writer_t *w)
{
    return json_double(w, 0.0 / 0.0);
}

static int write_roundtrip(json_writer_t *w)
{
    json_t *j = NULL;
    int rc;

    if(parse("{\"a\":[1,2.5,\"s\\u00e9\",{\"b\":null}],\"c\":true}", &j))
        return ~0;
    rc = json_value(w, j);
    json_free(j);
    return rc;
}

static int write_nul_key(json_writer_t *w)
{
    json_t *j = NULL;
    int rc;

    /* keys that differ after a NUL stay apart */
    if(parse("{\"a\\u0000b\":1,\"a\":2}", &j))
        return ~0;
    rc = json_value(w, j);
    json_free(j);
    return rc;
}

static void test_json_write(void)
{
    CHECK(written(write_doc) == 0);
    CHECK(!strcmp(json_out, "{\"id\":-42,"
                "\"name\":\"\\u003cscript\\u003e\\\"x\\\"\\u0026\\\\\\n\\u2028\","
                "\"bad\":\"a\\ufffdb\","
                "\"list\":[0.5,true,null,{}],"
                "\"ctl\":\"\\u0001\"}"));
    CHECK(written(write_no_key) != 0);
    CHECK(written(write_two) != 0);
    CHECK(written(write_open) != 0);
    CHECK(written(write_mismatch) != 0);
    CHECK(written(write_nan) != 0);
    CHECK(written(write_roundtrip) == 0);
    CHECK(!strcmp(json_out,
                "{\"a\":[1,2.5,\"s\xc3\xa9\",{\"b\":null}],\"c\":true}"));
    CHECK(written(write_nul_key) == 0);
    CHECK(!strcmp(json_out, "{\"a\\u0000b\":1,\"a\":2}"));
}

#ifdef SSL_OPENSSL
/* the crypto interface (klin/crypto.h) against published vectors: SHA-256
   (FIPS 180-2 "abc"), HMAC-SHA256 (RFC 4231 case 2), PBKDF2-HMAC-SHA256
   (RFC 7914 section 11), AES-256-CBC (NIST SP 800-38A F.2.5) */
static int hex_is(const unsigned char *b, size_t n, const char *hex)
{
    char buf[2 * KC_MD_MAX + 1];
    size_t i;

    if(n * 2 >= sizeof buf || strlen(hex) != n * 2)
        return 0;
    for(i = 0; i < n; ++i)
        sprintf(buf + 2 * i, "%02x", b[i]);
    return !strcmp(buf, hex);
}

static void test_crypto(void)
{
    static const unsigned char key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
        0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
        0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    static const unsigned char iv[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15 };
    static const unsigned char pt[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e,
        0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    unsigned char out[KC_MD_MAX], ct[64], back[64];
    size_t n, n2, total;
    kc_hmac_t *h = NULL;
    kc_cipher_t *c = NULL;
    char wiped[8] = "secret!";

    CHECK(kc_digest(KC_SHA256, "abc", 3, out, &n) == 0 && hex_is(out, n,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK(kc_md_size(KC_SHA256) == 32 && kc_md_size(KC_SHA1) == 20 &&
            kc_md_size(KC_MD5) == 16);
    CHECK(kc_md_from_name("SHA256") == KC_SHA256 &&
            kc_md_from_name("ripemd160") == KC_RIPEMD160 &&
            kc_md_from_name("sha512") == 0 && kc_md_from_name(NULL) == 0);

    CHECK(kc_hmac(KC_SHA256, "Jefe", 4, "what do ya want for nothing?", 28,
                out, &n) == 0 && hex_is(out, n,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    /* a reused context: the same MAC for the message in parts, twice */
    CHECK(kc_hmac_new(KC_SHA256, "Jefe", 4, &h) == 0);
    if(h)
    {
        for(n2 = 0; n2 < 2; ++n2)
        {
            CHECK(kc_hmac_init(h) == 0 &&
                    kc_hmac_update(h, "what do ya ", 11) == 0 &&
                    kc_hmac_update(h, "want for nothing?", 17) == 0 &&
                    kc_hmac_final(h, out, &n) == 0 && hex_is(out, n,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        }
        kc_hmac_free(h);
    }

    CHECK(kc_pbkdf2_sha256("passwd", 6, (const unsigned char *) "salt", 4, 1,
                out, 32) == 0 && hex_is(out, 32,
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"));

    /* AES-256-CBC: the NIST block, then the PKCS #7 padding block */
    CHECK(kc_cipher_key_len(KC_AES_256_CBC) == 32 &&
            kc_cipher_iv_len(KC_AES_256_CBC) == 16 &&
            kc_cipher_block_size(KC_AES_256_CBC) == 16);
    CHECK(kc_cipher_new(KC_AES_256_CBC, 1, key, iv, &c) == 0);
    total = 0;
    if(c)
    {
        CHECK(kc_cipher_update(c, ct, &n, pt, sizeof pt) == 0);
        total = n;
        CHECK(kc_cipher_final(c, ct + total, &n) == 0);
        total += n;
        kc_cipher_free(c);
        c = NULL;
    }
    CHECK(total == 32 && hex_is(ct, 16, "f58c4c04d6e5f1ba779eabfb5f7bfbd6"));
    CHECK(kc_cipher_new(KC_AES_256_CBC, 0, key, iv, &c) == 0);
    if(c)
    {
        CHECK(kc_cipher_update(c, back, &n, ct, total) == 0);
        CHECK(kc_cipher_final(c, back + n, &n2) == 0);
        CHECK(n + n2 == sizeof pt && !memcmp(back, pt, sizeof pt));
        kc_cipher_free(c);
        c = NULL;
    }
    /* a wrong key: the padding check fails */
    back[0] = 0;
    CHECK(kc_cipher_new(KC_AES_256_CBC, 0, iv, key, &c) == 0);
    if(c)
    {
        (void) kc_cipher_update(c, back, &n, ct, total);
        CHECK(kc_cipher_final(c, back + n, &n2) != 0 ||
                memcmp(back, pt, sizeof pt));
        kc_cipher_free(c);
    }

    CHECK(kc_memeq("abc", "abc", 3) && !kc_memeq("abc", "abd", 3));
    CHECK(kc_random(out, sizeof out) == 0);
    kc_cleanse(wiped, sizeof wiped);
    CHECK(!memcmp(wiped, "\0\0\0\0\0\0\0\0", 8));

    /* AES-256-GCM: the GCM specification's test cases 13 and 14 (zero key
       and nonce; no plaintext, then one zero block), then forgeries */
    {
        unsigned char k[KC_AEAD_KEY] = { 0 }, nonce[KC_AEAD_NONCE] = { 0 },
                      zero[16] = { 0 }, sealed[16], tag[KC_AEAD_TAG],
                      back[16];

        CHECK(kc_aead_seal(k, nonce, NULL, 0, NULL, 0, NULL, tag) == 0 &&
                hex_is(tag, sizeof tag, "530f8afbc74536b9a963b4f1c4cb738b"));
        CHECK(kc_aead_seal(k, nonce, NULL, 0, zero, 16, sealed, tag) == 0 &&
                hex_is(sealed, 16, "cea7403d4d606b6e074ec5d3baf39d18") &&
                hex_is(tag, sizeof tag, "d0d1c8a799996bf0265b98b5d48ab919"));
        CHECK(kc_aead_open(k, nonce, NULL, 0, sealed, 16, tag, back) == 0 &&
                !memcmp(back, zero, 16));
        /* with additional data: it must match too */
        CHECK(kc_aead_seal(k, nonce, "sid|1", 5, zero, 16, sealed, tag) == 0);
        CHECK(kc_aead_open(k, nonce, "sid|1", 5, sealed, 16, tag, back) == 0);
        CHECK(kc_aead_open(k, nonce, "sid|2", 5, sealed, 16, tag, back) != 0);
        sealed[3] ^= 1;
        CHECK(kc_aead_open(k, nonce, "sid|1", 5, sealed, 16, tag, back) != 0);
        sealed[3] ^= 1;
        tag[0] ^= 0x80;
        CHECK(kc_aead_open(k, nonce, "sid|1", 5, sealed, 16, tag, back) != 0);
        tag[0] ^= 0x80;
        k[0] = 1;
        CHECK(kc_aead_open(k, nonce, "sid|1", 5, sealed, 16, tag, back) != 0);
    }

    /* base64 from a client: only the alphabet, '=' only at the end (a byte
       over 0x7f made LibU read out of its table: found by fuzzing) */
    {
        unsigned char raw[16];
        size_t rlen;

        rlen = sizeof raw;
        CHECK(klin_b64_decode("aGk=", 4, raw, &rlen) == 0 && rlen == 2 &&
                !memcmp(raw, "hi", 2));
        rlen = sizeof raw;
        CHECK(klin_b64_decode("aG\xc6k", 4, raw, &rlen) != 0);
        rlen = sizeof raw;
        CHECK(klin_b64_decode("a=Gk", 4, raw, &rlen) != 0);
        rlen = sizeof raw;
        CHECK(klin_b64_decode("aG===", 5, raw, &rlen) != 0);
        rlen = sizeof raw;
        CHECK(klin_b64_decode("aG k", 4, raw, &rlen) != 0);
        rlen = sizeof raw;
        CHECK(klin_b64_decode("aGk", 3, raw, &rlen) != 0);  /* unpadded */
        /* an exact fit, and one byte short (LibU wrote 3 bytes here) */
        memset(raw, 0x55, sizeof raw);
        rlen = 2;
        CHECK(klin_b64_decode("aGk=", 4, raw, &rlen) == 0 && rlen == 2 &&
                raw[2] == 0x55);
        rlen = 1;
        CHECK(klin_b64_decode("aGk=", 4, raw, &rlen) != 0);
    }
}
#endif

int main(void)
{
    test_header_fields();
    test_header_limits();
    test_field_reuse();
    test_timer();
    test_translate();
    test_json_parse();
#ifdef SSL_OPENSSL
    test_crypto();
#endif
    test_json_write();
#ifdef SSL_OPENSSL
    test_auth();
#endif

    printf("%d unit checks, %d failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
