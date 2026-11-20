/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* Hashes for HTTP authentication: Digest HA1 and response values, and the
 * PBKDF2 password hashes Basic authentication checks against */

#include "klin_conf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <u/libu.h>
#include <klin/auth.h>
#include <klin/utils.h>

#include <klin/crypto.h>

enum { AUTH_SALT_SZ = 16, AUTH_KEY_SZ = 32 };

static const char AUTH_PBKDF2_PREFIX[] = "pbkdf2-sha256$";

int auth_alg_from_name(const char *name)
{
    if(name == NULL)
        return 0;
    if(!strcasecmp(name, "MD5"))
        return AUTH_ALG_MD5;
    if(!strcasecmp(name, "SHA-256"))
        return AUTH_ALG_SHA256;
    return 0;
}

const char *auth_alg_name(int alg)
{
    return alg == AUTH_ALG_MD5 ? "MD5" : "SHA-256";
}

#ifdef SSL_OPENSSL

int auth_hash_hex(int alg, const char *data, size_t len, char hex[AUTH_HEX_SZ])
{
    unsigned char md[KC_MD_MAX];
    size_t mdlen = 0;

    dbg_return_if (data == NULL, ~0);
    dbg_return_if (hex == NULL, ~0);
    dbg_return_if (alg != AUTH_ALG_MD5 && alg != AUTH_ALG_SHA256, ~0);

    dbg_err_if(kc_digest(alg == AUTH_ALG_MD5 ? KC_MD5 : KC_SHA256, data, len,
                md, &mdlen));

    u_tohex(hex, (const char *) md, mdlen);

    return 0;
err:
    return ~0;
}

/* hash "a:b:c..." (the parts joined with ':') */
static int auth_hash_parts(int alg, char hex[AUTH_HEX_SZ], const char **parts,
        size_t n)
{
    char buf[2048];
    size_t i, off = 0, l;

    for(i = 0; i < n; ++i)
    {
        dbg_err_if(parts[i] == NULL);
        l = strlen(parts[i]);
        dbg_err_if(off + l + 1 >= sizeof buf);
        if(i)
            buf[off++] = ':';
        memcpy(buf + off, parts[i], l);
        off += l;
    }

    return auth_hash_hex(alg, buf, off, hex);
err:
    return ~0;
}

int auth_digest_ha1(int alg, const char *user, const char *realm,
        const char *password, char hex[AUTH_HEX_SZ])
{
    const char *parts[3] = { user, realm, password };

    return auth_hash_parts(alg, hex, parts, 3);
}

int auth_digest_response(int alg, const char *ha1, const char *nonce,
        const char *nc, const char *cnonce, const char *method,
        const char *uri, char hex[AUTH_HEX_SZ])
{
    char ha2[AUTH_HEX_SZ];
    const char *a2[2] = { method, uri };
    const char *rs[6] = { ha1, nonce, nc, cnonce, "auth", ha2 };

    dbg_err_if(auth_hash_parts(alg, ha2, a2, 2));

    return auth_hash_parts(alg, hex, rs, 6);
err:
    return ~0;
}

static int auth_pbkdf2(const char *password, const unsigned char *salt,
        unsigned int iterations, unsigned char key[AUTH_KEY_SZ])
{
    return kc_pbkdf2_sha256(password, strlen(password), salt, AUTH_SALT_SZ,
            iterations, key, AUTH_KEY_SZ);
}

int auth_password_hash(const char *password, unsigned int iterations,
        char *out, size_t size)
{
    unsigned char salt[AUTH_SALT_SZ], key[AUTH_KEY_SZ];
    char salt64[32], key64[64];
    int n;

    dbg_return_if (password == NULL, ~0);
    dbg_return_if (out == NULL, ~0);
    dbg_return_if (iterations == 0, ~0);

    dbg_err_if(kc_random(salt, sizeof salt));
    dbg_err_if(auth_pbkdf2(password, salt, iterations, key));

    dbg_err_if(u_b64_encode(salt, sizeof salt, salt64, sizeof salt64));
    dbg_err_if(u_b64_encode(key, sizeof key, key64, sizeof key64));

    n = snprintf(out, size, "%s%u$%s$%s", AUTH_PBKDF2_PREFIX, iterations,
            salt64, key64);
    dbg_err_if(n < 0 || (size_t) n >= size);

    kc_cleanse(key, sizeof key);

    return 0;
err:
    kc_cleanse(key, sizeof key);
    return ~0;
}

int auth_password_verify(const char *password, const char *stored)
{
    unsigned char salt[AUTH_SALT_SZ + 4], want[AUTH_KEY_SZ + 4],
                  key[AUTH_KEY_SZ];
    char copy[AUTH_PASSWORD_SZ], *p, *salt64, *key64, *end;
    size_t saltlen = sizeof salt, wantlen = sizeof want;
    unsigned long iterations;
    int rc;

    nop_err_if(password == NULL || stored == NULL);
    nop_err_if(strncmp(stored, AUTH_PBKDF2_PREFIX,
                sizeof AUTH_PBKDF2_PREFIX - 1));
    nop_err_if(u_strlcpy(copy, stored + sizeof AUTH_PBKDF2_PREFIX - 1,
                sizeof copy));

    /* <iterations>$<salt>$<key> */
    iterations = strtoul(copy, &end, 10);
    nop_err_if(end == copy || *end != '$' || iterations == 0 ||
            iterations > 100000000);
    salt64 = end + 1;
    nop_err_if((p = strchr(salt64, '$')) == NULL);
    *p = '\0';
    key64 = p + 1;

    nop_err_if(klin_b64_decode(salt64, strlen(salt64), salt, &saltlen));
    nop_err_if(klin_b64_decode(key64, strlen(key64), want, &wantlen));
    nop_err_if(saltlen != AUTH_SALT_SZ || wantlen != AUTH_KEY_SZ);

    nop_err_if(auth_pbkdf2(password, salt, (unsigned int) iterations, key));

    rc = kc_memeq(key, want, AUTH_KEY_SZ) ? 0 : ~0;
    kc_cleanse(key, sizeof key);

    return rc;
err:
    return ~0;
}

#else /* no OpenSSL: no authentication */

int auth_hash_hex(int alg, const char *data, size_t len, char hex[AUTH_HEX_SZ])
{
    u_unused_args(alg, data, len, hex);
    return ~0;
}

int auth_digest_ha1(int alg, const char *user, const char *realm,
        const char *password, char hex[AUTH_HEX_SZ])
{
    u_unused_args(alg, user, realm, password, hex);
    return ~0;
}

int auth_digest_response(int alg, const char *ha1, const char *nonce,
        const char *nc, const char *cnonce, const char *method,
        const char *uri, char hex[AUTH_HEX_SZ])
{
    u_unused_args(alg, ha1, nonce, nc, cnonce, method, uri, hex);
    return ~0;
}

int auth_password_hash(const char *password, unsigned int iterations,
        char *out, size_t size)
{
    u_unused_args(password, iterations, out, size);
    return ~0;
}

int auth_password_verify(const char *password, const char *stored)
{
    u_unused_args(password, stored);
    return ~0;
}

#endif
