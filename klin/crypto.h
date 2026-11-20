/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_CRYPTO_H_
#define _KLIN_CRYPTO_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Klin's cryptography interface (doc/CRYPTO). Every hash, MAC, cipher and
 * random byte Klin uses goes through these functions; only their backend
 * (src/libutils/crypto.c) and the TLS layer (src/libtls, src/libio/iossl.c)
 * call the crypto library, OpenSSL 3. Without OpenSSL they fail. */

/* digests (and HMAC hashes) */
enum {
    KC_MD5 = 1,
    KC_SHA1,
    KC_SHA256,
    KC_RIPEMD160
};

/* ciphers */
enum {
    KC_AES_256_CBC = 1
};

/* sizes, the same as OpenSSL's EVP_MAX_*: session and page formats depend
 * on them */
enum {
    KC_MD_MAX = 64,             /* largest digest                        */
    KC_KEY_MAX = 64,            /* largest cipher key (buffers)          */
    KC_IV_MAX = 16,             /* largest cipher IV                     */
    KC_BLOCK_MAX = 32           /* largest cipher block                  */
};

/* digest name ("md5", "sha1", "sha256", "ripemd160", any case) to KC_*,
 * 0 if unknown */
int kc_md_from_name(const char *name);
size_t kc_md_size(int md);
int kc_digest(int md, const void *data, size_t len, unsigned char *out,
        size_t *outlen);

/* HMAC: one-shot, or a keyed context reused for many messages */
int kc_hmac(int md, const void *key, size_t keylen, const void *data,
        size_t len, unsigned char *out, size_t *outlen);
typedef struct kc_hmac_s kc_hmac_t;
int kc_hmac_new(int md, const void *key, size_t keylen, kc_hmac_t **ph);
int kc_hmac_init(kc_hmac_t *h);
int kc_hmac_update(kc_hmac_t *h, const void *data, size_t len);
int kc_hmac_final(kc_hmac_t *h, unsigned char *out, size_t *outlen);
void kc_hmac_free(kc_hmac_t *h);

/* PBKDF2-HMAC-SHA256 */
int kc_pbkdf2_sha256(const char *password, size_t pwlen,
        const unsigned char *salt, size_t saltlen, unsigned int iterations,
        unsigned char *out, size_t outlen);

/* random bytes from a cryptographically secure generator */
int kc_random(void *buf, size_t len);

/* compare in constant time: 1 if equal */
int kc_memeq(const void *a, const void *b, size_t len);

/* wipe memory (not optimised away) */
void kc_cleanse(void *p, size_t len);

/* symmetric ciphers (PKCS #7 padding), streamed */
typedef struct kc_cipher_s kc_cipher_t;
size_t kc_cipher_key_len(int cipher);
size_t kc_cipher_iv_len(int cipher);
size_t kc_cipher_block_size(int cipher);
int kc_cipher_new(int cipher, int encrypt, const unsigned char *key,
        const unsigned char *iv, kc_cipher_t **pc);
int kc_cipher_update(kc_cipher_t *c, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen);
int kc_cipher_final(kc_cipher_t *c, unsigned char *out, size_t *outlen);
void kc_cipher_free(kc_cipher_t *c);

/* authenticated encryption (AES-256-GCM): 'out' holds 'len' bytes; open
 * fails, and writes nothing usable, unless the tag matches the key, nonce,
 * additional data and ciphertext. A nonce must never be used twice with a
 * key (draw it with kc_random()) */
enum {
    KC_AEAD_KEY = 32,           /* AES-256 key                           */
    KC_AEAD_NONCE = 12,         /* GCM nonce                             */
    KC_AEAD_TAG = 16            /* GCM tag                               */
};
int kc_aead_seal(const unsigned char *key, const unsigned char *nonce,
        const void *aad, size_t aadlen, const void *in, size_t len,
        unsigned char *out, unsigned char *tag);
int kc_aead_open(const unsigned char *key, const unsigned char *nonce,
        const void *aad, size_t aadlen, const void *in, size_t len,
        const unsigned char *tag, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
