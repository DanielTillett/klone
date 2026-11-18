/* Isolated regression tests for verbatim production functions.
 * LibU allocation/string operations and network reads are test doubles;
 * this suite does not replace an integration build of the server. */
#define _CRT_SECURE_NO_WARNINGS
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <klone/md5.h>

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
enum { URLCPY_VERBATIM, URLCPY_ENCODE, URLCPY_DECODE };
enum { HEXCPY_VERBATIM, HEXCPY_ENCODE, HEXCPY_DECODE };
enum { HTMLCPY_VERBATIM, HTMLCPY_ENCODE, HTMLCPY_DECODE };
enum { SQLCPY_VERBATIM, SQLCPY_ENCODE, SQLCPY_DECODE };

static int u_strlcpy(char *d, const char *s, size_t size)
{
    size_t n = strlen(s);
    if (!size) return -1;
    if (n >= size) n = size - 1;
    memmove(d, s, n);
    d[n] = '\0';
    return 0;
}

typedef struct { char data[2048]; size_t len; } u_string_t;
static int fail_copy, fail_clear, fail_process, processed, live_strings;
static int u_string_create(const char *s, size_t n, u_string_t **out)
{
    (void)s; (void)n;
    *out = calloc(1, sizeof(**out));
    if (!*out) return -1;
    ++live_strings;
    return 0;
}
static void u_string_free(u_string_t *s) { if (s) { --live_strings; free(s); } }
static size_t u_string_len(u_string_t *s) { return s->len; }
static const char *u_string_c(u_string_t *s) { return s->data; }
static int u_string_reserve(u_string_t *s, size_t n)
{ (void)s; return n >= sizeof(s->data) ? -1 : 0; }
static int u_string_set_length(u_string_t *s, size_t n)
{
    if (n >= sizeof(s->data)) return -1;
    s->len = n; s->data[n] = '\0'; return 0;
}
static int u_string_append(u_string_t *s, const char *data, size_t n)
{
    if (n >= sizeof(s->data) - s->len) return -1;
    memcpy(s->data + s->len, data, n);
    return u_string_set_length(s, s->len + n);
}
static int u_string_clear(u_string_t *s)
{ return fail_clear ? -1 : u_string_set_length(s, 0); }
static int u_string_copy(u_string_t *d, u_string_t *s)
{
    if (fail_copy) return -1;
    *d = *s; return 0;
}
static int u_string_aprintf(u_string_t *s, const char *fmt, int slash, ...)
{
    int rc;
    va_list args;
    va_start(args, slash);
    if (strcmp(fmt, "%c%s") == 0)
        rc = snprintf(s->data + s->len, sizeof(s->data) - s->len,
                      fmt, slash, va_arg(args, const char *));
    else
        rc = snprintf(s->data + s->len, sizeof(s->data) - s->len, fmt, slash);
    va_end(args);
    if (rc < 0 || (size_t)rc >= sizeof(s->data) - s->len) return -1;
    s->len += (size_t)rc; return 0;
}
static int u_snprintf(char *out, size_t size, const char *fmt, int value)
{
    int n = snprintf(out, size, fmt, value);
    return n < 0 || (size_t)n >= size ? -1 : 0;
}
#ifdef _WIN32
#define strtok_r strtok_s
#endif
static int u_isnl(char c) { return c == '\r' || c == '\n'; }
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
static int u_getline_limit(io_t *io, u_string_t *s, size_t limit)
{
    const char *line = io->lines[io->offset];
    size_t n;
    if (!line || fail_clear) return -1;
    n = strlen(line);
    if (n > limit || n == 0 || line[n - 1] != '\n') return -1;
    ++io->offset;
    if (u_string_set_length(s, 0)) return -1;
    return u_string_append(s, line, n - 1);
}
static int header_process_line(header_t *h, u_string_t *s, int mode)
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
static int u_file_open(const char *path, int flags, io_t **out)
{ (void)path; (void)flags; *out = &file_input; return 0; }
static ssize_t io_write(io_t *io, const char *buf, size_t n)
{
    (void)io; (void)buf;
    if (n > 4096) { ++fail_process; return -1; }
    written += n; return (ssize_t)n;
}
static void io_free(io_t *io) { (void)io; ++freed; }

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
    const char *input[] = {"/", "/..", "/../../a", "/a/b/../c/", "/a/../../..", "\\a\\b\\..\\c"};
    const char *expected[] = {"/", "/", "/a", "/a/c/", "/", "/a/c"};
    char buffer[128];
    size_t i;
    for (i = 0; i < sizeof(input) / sizeof(*input); ++i) {
        strcpy(buffer, input[i]);
        CHECK(u_uri_normalize(buffer) == 0);
        CHECK(strcmp(buffer, expected[i]) == 0);
        CHECK(live_strings == 0);
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
    CHECK(live_strings == 0);
    io.offset = 0; fail_process = 1;
    CHECK(header_load_ex(&h, &io, 0) != 0 && live_strings == 0);
    fail_process = 0; fail_clear = 1; io.offset = 0;
    CHECK(header_load_ex(&h, &io, 0) != 0 && live_strings == 0);
    fail_process = 0;
    {
        const char *incomplete[] = {"X: one\r\n", NULL};
        const char *folded[] = {"X: one\r\n", " two\r\n", "\r\n", NULL};
        const char *many[260];
        size_t i;
        io.offset = 0; io.lines = incomplete;
        CHECK(header_load_ex(&h, &io, 0) != 0 && live_strings == 0);
        io.offset = 0; io.lines = folded;
        CHECK(header_load_ex(&h, &io, 0) != 0 && live_strings == 0);
        for (i = 0; i < 258; ++i) many[i] = "X: one\r\n";
        many[258] = "\r\n"; many[259] = NULL;
        io.offset = 0; io.lines = many;
        CHECK(header_load_ex(&h, &io, 0) != 0 && live_strings == 0);
    }
    io.lines = lines;
    fail_clear = 0; io.offset = 1; fail_process = 1;
    CHECK(header_load_ex(&h, &io, 0) != 0 && live_strings == 0);
    CHECK(io_mem_seek(&mem, 3) == 3 && mem.off == 3);
    CHECK(io_mem_seek(&mem, 4) == -1 && mem.off == 3);
    mem.size = 0; mem.off = 0;
    CHECK(io_mem_seek(&mem, 0) == 0);
}

static void test_file_supplier(void)
{
    request_t rq = {NULL, 0};
    io_t output = {NULL, 0, 0, 0, NULL};
    response_t rs = {&output, 0};
    file_input.data = "abc"; file_input.length = 3;
    file_input.offset = 0; file_input.error = 0;
    written = 0; freed = 0;
    CHECK(fs_serve(&rq, &rs) == 0 && written == 3 && freed == 1);
    file_input.offset = 0; file_input.error = 1;
    written = 0; freed = 0; fail_process = 0;
    CHECK(fs_serve(&rq, &rs) != 0 && written == 3 && freed == 1);
    CHECK(fail_process == 0); /* negative reads must never reach io_write */
}

int main(void)
{
    test_search(); test_encodings(); test_lengths(); test_paths();
    test_hashes(); test_headers_and_seek(); test_file_supplier();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
