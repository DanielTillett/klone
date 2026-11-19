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

int main(void)
{
    test_header_fields();
    test_header_limits();
    test_field_reuse();
    test_timer();
    test_translate();
#ifdef SSL_OPENSSL
    test_auth();
#endif

    printf("%d unit checks, %d failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
