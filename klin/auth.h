/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_AUTH_H_
#define _KLIN_AUTH_H_

#include <stddef.h>
#include <klin/http.h>
#include <klin/request.h>
#include <klin/response.h>
#include <klin/vhost.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HTTP authentication (Basic and Digest, RFC 7617 and RFC 7616), set up in
 * a vhost's "auth" block (doc/AUTH). The hashing helpers need OpenSSL. */

enum {
    AUTH_ALG_MD5 = 1,           /* Digest algorithm=MD5 (old clients)        */
    AUTH_ALG_SHA256 = 2,        /* Digest algorithm=SHA-256                  */
    AUTH_HEX_SZ = 65,           /* a SHA-256 hex digest and its NUL          */
    AUTH_PASSWORD_SZ = 128,     /* a stored password hash and its NUL        */
    AUTH_PBKDF2_ITERATIONS = 100000     /* default for new password hashes  */
};

/* lowercase hex digest of 'len' bytes of 'data' */
int auth_hash_hex(int alg, const char *data, size_t len, char hex[AUTH_HEX_SZ]);

/* Digest HA1, H(user:realm:password): what a user's "digest" line stores */
int auth_digest_ha1(int alg, const char *user, const char *realm,
        const char *password, char hex[AUTH_HEX_SZ]);

/* the Digest "response" for qop=auth from the stored HA1 */
int auth_digest_response(int alg, const char *ha1, const char *nonce,
        const char *nc, const char *cnonce, const char *method,
        const char *uri, char hex[AUTH_HEX_SZ]);

/* "pbkdf2-sha256$<iterations>$<salt>$<hash>" (base64) for a Basic password */
int auth_password_hash(const char *password, unsigned int iterations,
        char *out, size_t size);

/* 0 if 'password' matches a stored auth_password_hash() value */
int auth_password_verify(const char *password, const char *stored);

/* algorithm name ("SHA-256", "MD5", case-insensitive) to AUTH_ALG_*, 0 if
 * unknown */
int auth_alg_from_name(const char *name);
const char *auth_alg_name(int alg);

/* the server side (libhttp, auth.c) */
int auth_init_secret(http_t *h);
int auth_load(http_t *h, vhost_t *vhost);
int auth_check(http_t *h, request_t *rq);
int auth_challenge(http_t *h, request_t *rq, response_t *rs);

#ifdef __cplusplus
}
#endif

#endif
