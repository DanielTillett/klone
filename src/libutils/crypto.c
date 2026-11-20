/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* The OpenSSL 3 backend of Klin's cryptography interface (klin/crypto.h,
 * doc/CRYPTO). Outside this file only the TLS layer uses OpenSSL. */

#include "klin_conf.h"
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <u/libu.h>
#include <klin/crypto.h>

int kc_md_from_name(const char *name)
{
    static const struct { const char *name; int md; } mds[] = {
        { "md5", KC_MD5 }, { "sha1", KC_SHA1 }, { "sha256", KC_SHA256 },
        { "ripemd160", KC_RIPEMD160 }, { NULL, 0 }
    };
    size_t i;

    for(i = 0; name && mds[i].name; ++i)
        if(!strcasecmp(name, mds[i].name))
            return mds[i].md;
    return 0;
}

size_t kc_md_size(int md)
{
    switch(md)
    {
    case KC_MD5:        return 16;
    case KC_SHA1:       return 20;
    case KC_SHA256:     return 32;
    case KC_RIPEMD160:  return 20;
    }
    return 0;
}

size_t kc_cipher_key_len(int cipher)
{
    return cipher == KC_AES_256_CBC ? 32 : 0;
}

size_t kc_cipher_iv_len(int cipher)
{
    return cipher == KC_AES_256_CBC ? 16 : 0;
}

size_t kc_cipher_block_size(int cipher)
{
    return cipher == KC_AES_256_CBC ? 16 : 0;
}

#ifdef SSL_OPENSSL

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

/* the OpenSSL name of a digest */
static const char *kc_md_name(int md)
{
    switch(md)
    {
    case KC_MD5:        return "MD5";
    case KC_SHA1:       return "SHA1";
    case KC_SHA256:     return "SHA256";
    case KC_RIPEMD160:  return "RIPEMD160";
    }
    return NULL;
}

int kc_digest(int md, const void *data, size_t len, unsigned char *out,
        size_t *outlen)
{
    EVP_MD *m = NULL;
    unsigned int n = 0;
    int ok;

    dbg_return_if (out == NULL || (data == NULL && len), ~0);
    dbg_return_if (kc_md_name(md) == NULL, ~0);

    if((m = EVP_MD_fetch(NULL, kc_md_name(md), NULL)) == NULL)
        return ~0;
    ok = EVP_Digest(data, len, out, &n, m, NULL);
    EVP_MD_free(m);
    if(!ok)
        return ~0;
    if(outlen)
        *outlen = n;

    return 0;
}

struct kc_hmac_s
{
    EVP_MAC_CTX *ctx;
};

int kc_hmac_new(int md, const void *key, size_t keylen, kc_hmac_t **ph)
{
    OSSL_PARAM params[2];
    EVP_MAC *mac = NULL;
    kc_hmac_t *h = NULL;

    dbg_return_if (ph == NULL || key == NULL || kc_md_name(md) == NULL, ~0);

    dbg_err_if((h = u_zalloc(sizeof *h)) == NULL);
    dbg_err_if((mac = EVP_MAC_fetch(NULL, "HMAC", NULL)) == NULL);
    dbg_err_if((h->ctx = EVP_MAC_CTX_new(mac)) == NULL);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
            (char *) kc_md_name(md), 0);
    params[1] = OSSL_PARAM_construct_end();
    dbg_err_if(EVP_MAC_init(h->ctx, key, keylen, params) != 1);
    EVP_MAC_free(mac);

    *ph = h;
    return 0;
err:
    EVP_MAC_free(mac);
    kc_hmac_free(h);
    return ~0;
}

/* start a new message with the same key and digest */
int kc_hmac_init(kc_hmac_t *h)
{
    dbg_return_if (h == NULL, ~0);
    return EVP_MAC_init(h->ctx, NULL, 0, NULL) == 1 ? 0 : ~0;
}

int kc_hmac_update(kc_hmac_t *h, const void *data, size_t len)
{
    dbg_return_if (h == NULL, ~0);
    return EVP_MAC_update(h->ctx, data, len) == 1 ? 0 : ~0;
}

/* out must hold KC_MD_MAX bytes */
int kc_hmac_final(kc_hmac_t *h, unsigned char *out, size_t *outlen)
{
    size_t n = 0;

    dbg_return_if (h == NULL || out == NULL, ~0);
    if(EVP_MAC_final(h->ctx, out, &n, KC_MD_MAX) != 1)
        return ~0;
    if(outlen)
        *outlen = n;
    return 0;
}

void kc_hmac_free(kc_hmac_t *h)
{
    if(h)
    {
        EVP_MAC_CTX_free(h->ctx);
        u_free(h);
    }
}

int kc_hmac(int md, const void *key, size_t keylen, const void *data,
        size_t len, unsigned char *out, size_t *outlen)
{
    kc_hmac_t *h = NULL;
    int rc;

    if(kc_hmac_new(md, key, keylen, &h))
        return ~0;
    rc = (kc_hmac_update(h, data, len) || kc_hmac_final(h, out, outlen)) ?
        ~0 : 0;
    kc_hmac_free(h);

    return rc;
}

int kc_pbkdf2_sha256(const char *password, size_t pwlen,
        const unsigned char *salt, size_t saltlen, unsigned int iterations,
        unsigned char *out, size_t outlen)
{
    dbg_return_if (password == NULL || salt == NULL || out == NULL, ~0);

    return PKCS5_PBKDF2_HMAC(password, (int) pwlen, salt, (int) saltlen,
            (int) iterations, EVP_sha256(), (int) outlen, out) == 1 ? 0 : ~0;
}

int kc_random(void *buf, size_t len)
{
    dbg_return_if (buf == NULL && len, ~0);
    return RAND_bytes(buf, (int) len) == 1 ? 0 : ~0;
}

int kc_memeq(const void *a, const void *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

void kc_cleanse(void *p, size_t len)
{
    if(p && len)
        OPENSSL_cleanse(p, len);
}

struct kc_cipher_s
{
    EVP_CIPHER_CTX *ctx;
    int encrypt;
};

int kc_cipher_new(int cipher, int encrypt, const unsigned char *key,
        const unsigned char *iv, kc_cipher_t **pc)
{
    EVP_CIPHER *ci = NULL;
    kc_cipher_t *c = NULL;

    dbg_return_if (pc == NULL || key == NULL, ~0);
    dbg_return_if (cipher != KC_AES_256_CBC, ~0);

    dbg_err_if((c = u_zalloc(sizeof *c)) == NULL);
    c->encrypt = encrypt;
    dbg_err_if((c->ctx = EVP_CIPHER_CTX_new()) == NULL);
    dbg_err_if((ci = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL)) == NULL);
    dbg_err_if(EVP_CipherInit_ex2(c->ctx, ci, key, iv, encrypt ? 1 : 0, NULL)
            != 1);
    EVP_CIPHER_free(ci);

    *pc = c;
    return 0;
err:
    EVP_CIPHER_free(ci);
    kc_cipher_free(c);
    return ~0;
}

/* out must hold inlen + kc_cipher_block_size() bytes */
int kc_cipher_update(kc_cipher_t *c, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen)
{
    int n = 0;

    dbg_return_if (c == NULL || out == NULL || outlen == NULL, ~0);
    if(EVP_CipherUpdate(c->ctx, out, &n, in, (int) inlen) != 1)
        return ~0;
    *outlen = (size_t) n;
    return 0;
}

/* out must hold kc_cipher_block_size() bytes; fails on bad padding when
   decrypting (a wrong key) */
int kc_cipher_final(kc_cipher_t *c, unsigned char *out, size_t *outlen)
{
    int n = 0;

    dbg_return_if (c == NULL || out == NULL || outlen == NULL, ~0);
    if(EVP_CipherFinal_ex(c->ctx, out, &n) != 1)
        return ~0;
    *outlen = (size_t) n;
    return 0;
}

void kc_cipher_free(kc_cipher_t *c)
{
    if(c)
    {
        EVP_CIPHER_CTX_free(c->ctx);
        u_free(c);
    }
}

/* one AES-256-GCM pass; 'tag' is written when sealing, checked when
   opening */
static int kc_aead(int seal, const unsigned char *key,
        const unsigned char *nonce, const void *aad, size_t aadlen,
        const void *in, size_t len, unsigned char *out, unsigned char *tag)
{
    EVP_CIPHER *ci = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int n, rc = ~0;

    dbg_return_if (key == NULL || nonce == NULL || tag == NULL, ~0);
    dbg_return_if ((len && (in == NULL || out == NULL)) ||
            (aadlen && aad == NULL), ~0);
    dbg_return_if (len > INT_MAX || aadlen > INT_MAX, ~0);

    dbg_err_if((ctx = EVP_CIPHER_CTX_new()) == NULL);
    dbg_err_if((ci = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)) == NULL);
    dbg_err_if(EVP_CipherInit_ex2(ctx, ci, key, nonce, seal ? 1 : 0, NULL)
            != 1);
    if(aadlen)
        dbg_err_if(EVP_CipherUpdate(ctx, NULL, &n, aad, (int) aadlen) != 1);
    if(len)
        dbg_err_if(EVP_CipherUpdate(ctx, out, &n, in, (int) len) != 1);
    if(seal)
    {
        dbg_err_if(EVP_CipherFinal_ex(ctx, out + len, &n) != 1);
        dbg_err_if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                    KC_AEAD_TAG, tag) != 1);
    } else {
        dbg_err_if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                    KC_AEAD_TAG, tag) != 1);
        /* the tag is checked here: a forgery fails */
        nop_err_if(EVP_CipherFinal_ex(ctx, out + len, &n) != 1);
    }
    rc = 0;
err:
    EVP_CIPHER_free(ci);
    EVP_CIPHER_CTX_free(ctx);
    if(rc && !seal && len)
        kc_cleanse(out, len);
    return rc;
}

int kc_aead_seal(const unsigned char *key, const unsigned char *nonce,
        const void *aad, size_t aadlen, const void *in, size_t len,
        unsigned char *out, unsigned char *tag)
{
    return kc_aead(1, key, nonce, aad, aadlen, in, len, out, tag);
}

int kc_aead_open(const unsigned char *key, const unsigned char *nonce,
        const void *aad, size_t aadlen, const void *in, size_t len,
        const unsigned char *tag, unsigned char *out)
{
    /* EVP takes the expected tag through a non-const pointer */
    unsigned char t[KC_AEAD_TAG];

    dbg_return_if (tag == NULL, ~0);
    memcpy(t, tag, sizeof t);
    return kc_aead(0, key, nonce, aad, aadlen, in, len, out, t);
}

#else   /* no crypto library: everything fails */

int kc_digest(int md, const void *data, size_t len, unsigned char *out,
        size_t *outlen)
{
    u_unused_args(md, data, len, out, outlen);
    return ~0;
}

int kc_hmac_new(int md, const void *key, size_t keylen, kc_hmac_t **ph)
{
    u_unused_args(md, key, keylen, ph);
    return ~0;
}

int kc_hmac_init(kc_hmac_t *h) { u_unused_args(h); return ~0; }

int kc_hmac_update(kc_hmac_t *h, const void *data, size_t len)
{
    u_unused_args(h, data, len);
    return ~0;
}

int kc_hmac_final(kc_hmac_t *h, unsigned char *out, size_t *outlen)
{
    u_unused_args(h, out, outlen);
    return ~0;
}

void kc_hmac_free(kc_hmac_t *h) { u_unused_args(h); }

int kc_hmac(int md, const void *key, size_t keylen, const void *data,
        size_t len, unsigned char *out, size_t *outlen)
{
    u_unused_args(md, key, keylen, data, len, out, outlen);
    return ~0;
}

int kc_pbkdf2_sha256(const char *password, size_t pwlen,
        const unsigned char *salt, size_t saltlen, unsigned int iterations,
        unsigned char *out, size_t outlen)
{
    u_unused_args(password, pwlen, salt, saltlen, iterations, out, outlen);
    return ~0;
}

int kc_random(void *buf, size_t len)
{
    u_unused_args(buf, len);
    return ~0;
}

int kc_memeq(const void *a, const void *b, size_t len)
{
    const volatile unsigned char *x = a, *y = b;
    unsigned char d = 0;
    size_t i;

    for(i = 0; i < len; ++i)
        d |= x[i] ^ y[i];
    return d == 0;
}

void kc_cleanse(void *p, size_t len)
{
    volatile unsigned char *v = p;

    while(v && len--)
        *v++ = 0;
}

int kc_cipher_new(int cipher, int encrypt, const unsigned char *key,
        const unsigned char *iv, kc_cipher_t **pc)
{
    u_unused_args(cipher, encrypt, key, iv, pc);
    return ~0;
}

int kc_cipher_update(kc_cipher_t *c, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen)
{
    u_unused_args(c, out, outlen, in, inlen);
    return ~0;
}

int kc_cipher_final(kc_cipher_t *c, unsigned char *out, size_t *outlen)
{
    u_unused_args(c, out, outlen);
    return ~0;
}

void kc_cipher_free(kc_cipher_t *c) { u_unused_args(c); }

int kc_aead_seal(const unsigned char *key, const unsigned char *nonce,
        const void *aad, size_t aadlen, const void *in, size_t len,
        unsigned char *out, unsigned char *tag)
{
    u_unused_args(key, nonce, aad, aadlen, in, len, out, tag);
    return ~0;
}

int kc_aead_open(const unsigned char *key, const unsigned char *nonce,
        const void *aad, size_t aadlen, const void *in, size_t len,
        const unsigned char *tag, unsigned char *out)
{
    u_unused_args(key, nonce, aad, aadlen, in, len, tag, out);
    return ~0;
}

#endif  /* SSL_OPENSSL */
