/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */
/* Isolated regression tests for verbatim production functions.
 * LibU allocation/string operations and network reads are test doubles;
 * this suite does not replace an integration build of the server. */
#define _CRT_SECURE_NO_WARNINGS
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <klin/md5.h>

#ifdef _WIN32
typedef ptrdiff_t ssize_t;
#define strncasecmp _strnicmp
#else
#include <sys/types.h>
#include <strings.h>
#endif

#define dbg_err_if(c) do { if (c) goto err; } while (0)
#define dbg_return_if(c, r) do { if (c) return (r); } while (0)
#define dbg_ifb(c) if (c)
#define warn_err_ifm(c, message) dbg_err_if(c)
#define U_MIN(a, b) ((a) < (b) ? (a) : (b))
#define KLIN_UNCONST(p) ((void *)(uintptr_t)(const void *)(p))
enum { URLCPY_VERBATIM, URLCPY_ENCODE, URLCPY_DECODE };
enum { HEXCPY_VERBATIM, HEXCPY_ENCODE, HEXCPY_DECODE };
enum { HTMLCPY_VERBATIM, HTMLCPY_ENCODE, HTMLCPY_DECODE };
enum { SQLCPY_VERBATIM, SQLCPY_ENCODE, SQLCPY_DECODE };

static int fail_read, fail_process, processed;
#ifdef _WIN32
#define strtok_r strtok_s
#endif
static int u_isblank(char c) { return c == ' ' || c == '\t'; }

typedef struct { const char *length; } header_t;
typedef struct { header_t *header; size_t content_length; } request_t;
static const char *header_get_field_value(header_t *h, const char *name)
{ (void)name; return h->length; }
typedef struct {
    const char *data;
    size_t length, offset;
    int error;
    const char **lines;
} io_t;
static ssize_t io_read(io_t *io, char *buf, size_t size)
{
    size_t n = U_MIN(size, io->length - io->offset);
    if (!n) return io->error ? -1 : 0;
    memcpy(buf, io->data + io->offset, n); io->offset += n;
    return (ssize_t)n;
}
/* one line per call, like the real one: at most size - 1 bytes (a partial
   line if it does not fit), 0 at the end, -1 on a read error */
static ssize_t io_get_until(io_t *io, char stop_at, char *buf, size_t size)
{
    const char *line = io->lines[io->offset];
    size_t n;
    (void)stop_at;
    if (fail_read) return -1;
    if (!line) { buf[0] = 0; return 0; }
    n = U_MIN(strlen(line), size - 1);
    memcpy(buf, line, n); buf[n] = 0;
    ++io->offset;
    return (ssize_t)n;
}
static int header_process_line(header_t *h, const char *s, int mode)
{ (void)h; (void)s; (void)mode; ++processed; return fail_process ? -1 : 0; }
typedef struct { size_t off, size; } io_mem_t;

/* File supplier collaborators: exercise read errors without real sockets. */
enum { HM_HEAD = 1 };
typedef struct { io_t *output; int method; } response_t;
static io_t file_input;
static size_t written;
static int freed;
static io_t *response_io(response_t *rs) { return rs->output; }
static const char *request_get_resolved_filename(request_t *rq)
{ (void)rq; return __FILE__; }
static int response_set_content_length(response_t *rs, size_t n)
{ (void)rs; (void)n; return 0; }
static const char *u_guess_mime_type(const char *path)
{ (void)path; return "text/plain"; }
static int response_set_content_type(response_t *rs, const char *type)
{ (void)rs; (void)type; return 0; }
static int response_set_last_modified(response_t *rs, time_t t)
{ (void)rs; (void)t; return 0; }
static int response_print_header_to_io(response_t *rs, io_t *io)
{ (void)rs; (void)io; return 0; }
static int response_get_method(response_t *rs) { return rs->method; }
static ssize_t io_write(io_t *io, const char *buf, size_t n)
{
    (void)io; (void)buf;
    if (n > 4096) { ++fail_process; return -1; }
    written += n; return (ssize_t)n;
}
static void io_free(io_t *io) { (void)io; ++freed; }
/* the size fs_serve sees for the open file, and whether it closed the
 * connection because fewer bytes could be read */
static off_t file_size;
static int conn_closed;
enum { IO_FD_CLOSE = 1 };
static void *request_get_http(request_t *rq) { (void)rq; return NULL; }
/* fs_open() (the symlink policy, doc/FILES) has the server tests: here the
   file is open, regular, and file_size long */
static int fs_open(void *h, request_t *rq, const char *fqn, struct stat *st)
{
    (void)h; (void)rq; (void)fqn;
    memset(st, 0, sizeof *st); st->st_size = file_size;
    return 3;
}
static int io_fd_create(int fd, int flags, io_t **out)
{ (void)fd; (void)flags; *out = &file_input; return 0; }
static int close(int fd) { (void)fd; return 0; }
static void response_close_connection(response_t *rs)
{ (void)rs; ++conn_closed; }

#include "regression_functions.inc"

static int checks, failures;
#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #c); ++failures; } } while (0)

static void test_search(void)
{
    const char text[] = "abcabc";
    const char raw[] = {'a', 'b', 'c', 'a'};
    const char zero[] = {'x', '\0'};
    CHECK(u_strnstr(text, "", 0) == text);
    CHECK(u_strnstr(text, "a", 0) == NULL);
    CHECK(u_strnstr(text, "bc", 6) == text + 1);
    CHECK(u_strnstr(text, "cx", 6) == NULL);
    CHECK(u_strnstr(text, "abcd", 3) == NULL);
    CHECK(u_strnstr(raw, "ca", sizeof(raw)) == raw + 2);
    CHECK(u_strnstr(raw, "ab", 1) == NULL);
    CHECK(u_strnstr(zero, "y", 100) == NULL);
}

static void test_encodings(void)
{
    char out[1024], encoded[1024], raw[256];
    char short_escape[] = {'%', '4'}; /* deliberately not NUL terminated */
    size_t i;
    ssize_t n;
    CHECK(u_urlncpy(out, short_escape, sizeof(short_escape), URLCPY_DECODE) == -1);
    CHECK(u_urlncpy(out, "%", 1, URLCPY_DECODE) == -1);
    CHECK(u_urlncpy(out, "%GG", 3, URLCPY_DECODE) == -1);
    CHECK(u_urlncpy(out, "%4F+a", 5, URLCPY_DECODE) == 3);
    CHECK(strcmp(out, "O a") == 0);
    CHECK(u_hexncpy(out, "g0", 2, HEXCPY_DECODE) == -1);
    CHECK(u_hexncpy(out, "0Z", 2, HEXCPY_DECODE) == -1);
    CHECK(u_hexncpy(out, "?0", 2, HEXCPY_DECODE) == -1);
    CHECK(u_hexncpy(out, "0", 1, HEXCPY_DECODE) == -1);
    CHECK(u_hexncpy(out, "aF", 2, HEXCPY_DECODE) == 1);
    CHECK((unsigned char)out[0] == 0xaf);
    for (i = 0; i < sizeof(raw); ++i) raw[i] = (char)i;
    n = u_urlncpy(encoded, raw, sizeof(raw), URLCPY_ENCODE);
    CHECK(n > 0);
    CHECK(u_urlncpy(out, encoded, (size_t)n, URLCPY_DECODE) == 256);
    CHECK(memcmp(out, raw, 256) == 0);
    memset(out, '*', sizeof(out));
    CHECK(u_urlncpy_s(out, 3, "&", 1, URLCPY_ENCODE) == -1 && out[0] == '*');
    CHECK(u_urlncpy_s(out, 4, "&", 1, URLCPY_ENCODE) == 3);
    CHECK(strcmp(out, "%26") == 0);
    CHECK(u_hexncpy_s(out, 2, "x", 1, HEXCPY_ENCODE) == -1);
    CHECK(u_hexncpy_s(out, 3, "x", 1, HEXCPY_ENCODE) == 2);
    CHECK(u_hexncpy_s(out, 2, "ff", 2, HEXCPY_DECODE) == 1);
    CHECK(u_htmlncpy_s(out, 5, "&", 1, HTMLCPY_ENCODE) == -1);
    CHECK(u_htmlncpy_s(out, 6, "&", 1, HTMLCPY_ENCODE) == 5);
    CHECK(strcmp(out, "&amp;") == 0);
    CHECK(u_sqlncpy_s(out, 3, "'a", 2, SQLCPY_ENCODE) == -1);
    CHECK(u_sqlncpy_s(out, 4, "'a", 2, SQLCPY_ENCODE) == 3);
    CHECK(strcmp(out, "''a") == 0);
    CHECK(u_sqlncpy_s(out, 4, "''a", 3, SQLCPY_DECODE) == 2);
    CHECK(strcmp(out, "'a") == 0);
    n = u_hexncpy(encoded, raw, sizeof(raw), HEXCPY_ENCODE);
    CHECK(n == 512);
    CHECK(u_hexncpy(out, encoded, (size_t)n, HEXCPY_DECODE) == 256);
    CHECK(memcmp(out, raw, 256) == 0);
}

static void test_lengths(void)
{
    const char *invalid[] = {NULL, "", "-1", "+1", "1x", "1 2", "1\r", " \t",
        "999999999999999999999999999999999999999999999", NULL};
    header_t h = {"123"};
    request_t rq = {&h, 0};
    char limit[32];
    size_t i;
    CHECK(request_set_content_length(&rq) == 0 && rq.content_length == 123);
    h.length = "000";
    CHECK(request_set_content_length(&rq) == 0 && rq.content_length == 0);
    h.length = " \t123\t ";
    CHECK(request_set_content_length(&rq) == 0 && rq.content_length == 123);
    snprintf(limit, sizeof(limit), "%zu", (size_t)-1);
    h.length = limit;
    CHECK(request_set_content_length(&rq) == 0 && rq.content_length == (size_t)-1);
    for (i = 0; i < sizeof(invalid) / sizeof(*invalid) - 1; ++i) {
        h.length = invalid[i]; rq.content_length = 7;
        CHECK(request_set_content_length(&rq) != 0 && rq.content_length == 7);
    }
}

static void test_paths(void)
{
    const char *input[] = {"/", "/..", "/../../a", "/a/b/../c/", "/a/../../..", "\\a\\b\\..\\c",
                           "//a//b", "/a/./b/.", "/a/b/..", "/.../x", "/a/b/c/../../d/", "/a/../"};
    const char *expected[] = {"/", "/", "/a", "/a/c/", "/", "/a/c",
                              "/a/b", "/a/b", "/a", "/.../x", "/a/d/", "/"};
    char buffer[128];
    size_t i;
    for (i = 0; i < sizeof(input) / sizeof(*input); ++i) {
        strcpy(buffer, input[i]);
        CHECK(u_uri_normalize(buffer) == 0);
        CHECK(strcmp(buffer, expected[i]) == 0);
    }
    buffer[0] = '\0'; CHECK(u_uri_normalize(buffer) != 0);
    strcpy(buffer, "relative"); CHECK(u_uri_normalize(buffer) != 0);
}

static void test_hashes(void)
{
    char digest[MD5_DIGEST_BUFSZ];
    char binary[257];
    size_t i;
    io_t io = {"abc", 3, 0, 0, NULL};
    CHECK(u_md5io(&io, digest) == 0);
    CHECK(strcmp(digest, "900150983cd24fb0d6963f7d28e17f72") == 0);
    io.offset = 0; io.error = 1;
    CHECK(u_md5io(&io, digest) != 0);
    io.length = 0; io.offset = 0; io.error = 0;
    CHECK(u_md5io(&io, digest) == 0);
    CHECK(strcmp(digest, "d41d8cd98f00b204e9800998ecf8427e") == 0);
    /* Exercise full blocks, high-bit bytes and an unaligned source. */
    for (i = 0; i < 256; ++i) binary[i + 1] = (char)i;
    io.data = binary + 1; io.length = 256; io.offset = 0;
    CHECK(u_md5io(&io, digest) == 0);
    CHECK(strcmp(digest, "e2c865db4162bed963bfaa9ef6ac18f0") == 0);
    io.data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    io.length = 80; io.offset = 0;
    CHECK(u_md5io(&io, digest) == 0);
    CHECK(strcmp(digest, "57edf4a22be3c955ac49da2e2107b67a") == 0);
}

static void test_headers_and_seek(void)
{
    const char *lines[] = {"X-A: one\r\n", "X-B: two\r\n", "\r\n", NULL};
    io_t io = {NULL, 0, 0, 0, lines};
    header_t h = {NULL};
    io_mem_t mem = {0, 3};
    CHECK(header_load_ex(&h, &io, 0) == 0 && processed == 2);
    io.offset = 0; fail_process = 1;
    CHECK(header_load_ex(&h, &io, 0) != 0);
    fail_process = 0; fail_read = 1; io.offset = 0;
    CHECK(header_load_ex(&h, &io, 0) != 0);
    fail_process = 0; fail_read = 0;
    {
        const char *incomplete[] = {"X: one\r\n", NULL};
        const char *folded[] = {"X: one\r\n", " two\r\n", "\r\n", NULL};
        const char *many[260];
        size_t i;
        io.offset = 0; io.lines = incomplete;
        CHECK(header_load_ex(&h, &io, 0) != 0);
        io.offset = 0; io.lines = folded;
        CHECK(header_load_ex(&h, &io, 0) != 0);
        for (i = 0; i < 258; ++i) many[i] = "X: one\r\n";
        many[258] = "\r\n"; many[259] = NULL;
        io.offset = 0; io.lines = many;
        CHECK(header_load_ex(&h, &io, 0) != 0);
    }
    {
        /* 8192 bytes with the '\n' is the longest line accepted */
        static char fit[8193], over[8194];
        const char *ok[] = {fit, "\r\n", NULL}, *bad[] = {over, "\r\n", NULL};
        memset(fit, 'a', 8191); memcpy(fit, "X: ", 3); fit[8191] = '\n';
        memset(over, 'a', 8192); memcpy(over, "X: ", 3); over[8192] = '\n';
        processed = 0; io.offset = 0; io.lines = ok;
        CHECK(header_load_ex(&h, &io, 0) == 0 && processed == 1);
        io.offset = 0; io.lines = bad;
        CHECK(header_load_ex(&h, &io, 0) != 0);
    }
    io.lines = lines;
    fail_read = 0; io.offset = 1; fail_process = 1;
    CHECK(header_load_ex(&h, &io, 0) != 0);
    CHECK(io_mem_seek((io_t *) &mem, 3) == 3 && mem.off == 3);
    CHECK(io_mem_seek((io_t *) &mem, 4) == -1 && mem.off == 3);
    mem.size = 0; mem.off = 0;
    CHECK(io_mem_seek((io_t *) &mem, 0) == 0);
}

static void test_file_supplier(void)
{
    request_t rq = {NULL, 0};
    io_t output = {NULL, 0, 0, 0, NULL};
    response_t rs = {&output, 0};
    file_input.data = "abc"; file_input.length = 3;
    file_input.offset = 0; file_input.error = 0;
    written = 0; freed = 0; file_size = 3; conn_closed = 0;
    CHECK(fs_serve(&rq, &rs) == 0 && written == 3 && freed == 1);
    CHECK(conn_closed == 0);
    file_input.offset = 0; file_input.error = 1;
    written = 0; freed = 0; fail_process = 0; file_size = 6;
    CHECK(fs_serve(&rq, &rs) != 0 && written == 3 && freed == 1);
    CHECK(fail_process == 0); /* negative reads must never reach io_write */
    /* the file shrank after fstat(): fewer bytes than Content-Length */
    file_input.offset = 0; file_input.error = 0;
    written = 0; freed = 0; file_size = 6; conn_closed = 0;
    CHECK(fs_serve(&rq, &rs) == 0 && written == 3 && conn_closed == 1);
    /* the file grew: never more than Content-Length */
    file_input.offset = 0; written = 0; freed = 0; file_size = 2;
    CHECK(fs_serve(&rq, &rs) == 0 && written == 2 && freed == 1);
}

int main(void)
{
    test_search(); test_encodings(); test_lengths(); test_paths();
    test_hashes(); test_headers_and_seek(); test_file_supplier();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
