/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_TLS_PRV_H_
#define _KLIN_TLS_PRV_H_

#include "klin_conf.h"
#ifdef SSL_ON
#include <u/libu.h>
#include <klin/io.h>
#ifdef SSL_OPENSSL
#include <openssl/evp.h>
#include <openssl/ssl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* SSL_CTX initialization parameters.  Mapping of "verify_client" configuration
 * directive to vmode is done in the following way:
 *  "none"      -> SSL_VERIFY_NONE
 *  "optional"  -> SSL_VERIFY_PEER
 *  "require"   -> SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT */
struct tls_ctx_args_s
{
    const char *cert;       /* server certificate file (PEM) */
    const char *key;        /* server private key (PEM) */
    const char *certchain;  /* Server Certificate Authorities (PEM) */
    const char *ca;         /* Client Certification Authorities file (PEM) */
    const char *crl;        /* Certificate Revocation List (PEM) */
    const char *dh;         /* Diffie-Hellman parameters (PEM) */
    int crlopts;            /* CRL check mode: 'all' or 'client-only' */
    int depth;              /* max depth for the cert chain verification */
    int vmode;              /* SSL verification mode */
    int keymgr;             /* the private key is held by a key manager */
    int sandbox;            /* ... in a sandbox (doc/SANDBOX)           */
    /* protocol settings (doc/TLS) */
    const char *ciphers;    /* TLS 1.2 cipher list                      */
    const char *suites;     /* TLS 1.3 cipher suites (NULL: OpenSSL's)  */
    int minver;             /* TLS1_2_VERSION or TLS1_3_VERSION         */
    int ticket_period;      /* seconds a ticket key is used; 0: none    */
};

typedef struct tls_ctx_args_s tls_ctx_args_t;

/* used by tls.c and the io driver: the OpenSSL side of the TLS layer
   (the only code besides src/libutils/crypto.c that calls OpenSSL) */
#ifdef SSL_OPENSSL
int tls_keyproxy_use_key(SSL_CTX *c, EVP_PKEY *key, int sandbox);
int tls_keyproxy_use_key_file(SSL_CTX *c, const char *path, int sandbox);
int io_ssl_get_SSL(io_t *io_ssl, SSL **pssl);
BIO *bio_from_emb (const char *);
BIO *tls_get_file_bio(const char *res_name);
STACK_OF(X509_NAME) *tls_load_client_CA_file(const char *);
#endif
int tls_load_verify_locations(SSL_CTX *, const char *);
int tls_use_certificate_file(SSL_CTX *, const char *, int);
int tls_use_PrivateKey_file(SSL_CTX *, const char *, int, int, int);
int tls_use_certificate_chain(SSL_CTX *, const char *, int, 
        int (*)(char *, int, int, void *));
int tls_use_crls (SSL_CTX *ctx, tls_ctx_args_t *cargs);
int tls_verify_cb (int ok, X509_STORE_CTX *ctx);
char *tls_get_error (void);

#ifdef __cplusplus
}
#endif 

#endif /* SSL_ON */
#endif /* _KLIN_TLS_PRV_H_ */
