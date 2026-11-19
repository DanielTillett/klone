/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <u/libu.h>
#include <klin/session.h>
#include <klin/request.h>
#include <klin/response.h>
#include <klin/vars.h>
#include <klin/utils.h>
#include <klin/emb.h>
#include <klin/ses_prv.h>
#include <klin/codecs.h>
#ifdef SSL_ON
#include <openssl/hmac.h>
#include <openssl/rand.h>
#ifdef SSL_OPENSSL
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif
#endif

#define KL1_CLISES_DATA     "KL1_CLISES_DATA"
#define KL1_CLISES_MTIME    "KL1_CLISES_MTIME"
#define KL1_CLISES_HMAC     "KL1_CLISES_HMAC"
#define KL1_CLISES_IV       "KL1_CLISES_IV"

enum { HMAC_HEX_SIZE = 2*EVP_MAX_MD_SIZE + 1 };

/* calc the hmac of data+sid+mtime */
static int session_client_hmac(session_opt_t *so, char *hmac, size_t hmac_sz,
    const char *data, const char *sid, const char *mtime, const char *hex_iv)
{
    unsigned char mac[EVP_MAX_MD_SIZE];
    size_t mac_len;

    dbg_err_if (so == NULL);
    dbg_err_if (hmac == NULL);
    dbg_err_if (data == NULL);
    dbg_err_if (sid == NULL);
    dbg_err_if (mtime == NULL);
    /* hex_iv may be NULL */
    
#if SSL_OPENSSL
    /* hmac must be at least 'EVP_MAX_MD_SIZE*2 + 1' (it will be hex encoded) */
    dbg_err_if(hmac_sz < EVP_MAX_MD_SIZE*2 + 1);

    /* calc HMAC hash of the data buf + mtime (reuse stored key and md) */
    dbg_err_if(EVP_MAC_init(so->hmac_ctx, NULL, 0, NULL) != 1);
    dbg_err_if(EVP_MAC_update(so->hmac_ctx, (const unsigned char *)data, strlen(data)) != 1);
    dbg_err_if(EVP_MAC_update(so->hmac_ctx, (const unsigned char *)sid, strlen(sid)) != 1);
    dbg_err_if(EVP_MAC_update(so->hmac_ctx, (const unsigned char *)mtime, strlen(mtime)) != 1);
    if(hex_iv)
        dbg_err_if(EVP_MAC_update(so->hmac_ctx, (const unsigned char *)hex_iv, strlen(hex_iv)) != 1);
    dbg_err_if(EVP_MAC_final(so->hmac_ctx, mac, &mac_len, sizeof(mac)) != 1);
#endif


    /* encode the hash */
    dbg_err_if(u_hexncpy_s(hmac, hmac_sz, (const char *)mac, mac_len, HEXCPY_ENCODE) <= 0);

    return 0;
err:
    return -1;
}

static int session_client_save(session_t *ss)
{
    /* BUF_SIZE: cookie size + MAC size + gzip header + encryption padding  */
    enum { 
        MTIME_SIZE = 32, 
        BUF_SIZE = 2 * COOKIE_MAX_SIZE + 1
    };
    session_opt_t *so = ss->so;
    char hmac[HMAC_HEX_SIZE], ebuf[BUF_SIZE], mtime[MTIME_SIZE];
    char *buf = NULL, cipher_iv_hex[CIPHER_IV_LEN * 2 + 1];
    size_t sz;
    time_t now;

    dbg_err_if (ss == NULL);

    #ifdef SSL_ON
    if(ss->so->encrypt)
    {
        /* generate a new IV for each session */
        #ifdef SSL_OPENSSL
        dbg_err_if(RAND_bytes(ss->so->cipher_iv, CIPHER_IV_LEN) != 1);
        #endif


        /* hex encode the IV and save it in a cookie */
        dbg_err_if(u_hexncpy_s(cipher_iv_hex, sizeof(cipher_iv_hex), (const char *)ss->so->cipher_iv, CIPHER_IV_LEN,
            HEXCPY_ENCODE) <= 0);
        dbg_err_if(session_set_cookie(ss, KL1_CLISES_IV, cipher_iv_hex,
            0, NULL, NULL, 0));
    }
    #endif

    /* save the session data to freshly alloc'd buf of size sz */
    dbg_err_if(session_prv_save_to_buf(ss, &buf, &sz));

    warn_err_ifm(sz > COOKIE_MAX_SIZE, 
                "session data too big for client-side sessions");

    /* hex-encode the buffer */
    dbg_err_if(u_hexncpy_s(ebuf, sizeof(ebuf), buf, sz, HEXCPY_ENCODE) <= 0);

    dbg_err_if(session_set_cookie(ss, KL1_CLISES_DATA, ebuf, 0, NULL,
        NULL, 0));

    /* set mtime cookie */
    dbg_err_sif ((now = time(NULL)) == (time_t) -1);
    dbg_err_if (u_snprintf(mtime, sizeof mtime, "%d", (ss->mtime = (int) now)));
    dbg_err_if (session_set_cookie(ss, KL1_CLISES_MTIME, mtime, 0, NULL,
                NULL, 0));

    /* calc the HMAC */
    dbg_err_if(session_client_hmac(so, hmac, HMAC_HEX_SIZE,
        ebuf, ss->id, mtime, ss->so->encrypt ? cipher_iv_hex : NULL));

    /* store the hash in a cookie */
    dbg_err_if(session_set_cookie(ss, KL1_CLISES_HMAC, hmac, 0, NULL,
        NULL, 0));

    u_free(buf);

    return 0;
err:
    if(buf)
        u_free(buf);
    return ~0;
}

static int session_client_load(session_t *ss)
{
    session_opt_t *so = ss->so;
    char hmac[HMAC_HEX_SIZE], buf[COOKIE_MAX_SIZE];
    const char *cli_ebuf, *cli_hmac, *cli_mtime, *cli_iv;
    ssize_t c;

    dbg_err_if (ss == NULL);

    /* extract session data, mtime and hmac from cookies */
    cli_ebuf = request_get_cookie(ss->rq, KL1_CLISES_DATA);
    cli_mtime = request_get_cookie(ss->rq, KL1_CLISES_MTIME);
    cli_hmac = request_get_cookie(ss->rq, KL1_CLISES_HMAC);
    cli_iv = request_get_cookie(ss->rq, KL1_CLISES_IV);

    //nop_err_if(cli_ebuf == NULL || cli_mtime == NULL || cli_hmac == NULL);
    dbg_err_if(cli_ebuf == NULL || cli_mtime == NULL || cli_hmac == NULL);
    /* cli_iv may be NULL */

    /* calc the HMAC */
    dbg_err_if(session_client_hmac(so, hmac, HMAC_HEX_SIZE,
        cli_ebuf, ss->id, cli_mtime, ss->so->encrypt ? cli_iv : NULL));

    /* compare HMACs */
    if(strlen(hmac) != strlen(cli_hmac) ||
        CRYPTO_memcmp(hmac, cli_hmac, strlen(hmac)) != 0)
    {
        session_remove(ss); /* remove all bad stale data */
        warn_err("HMAC don't match, rejecting session data");
    }

    /* hash ckeched. decode/uncompress/decrypt session data */

    /* hex decode and save current cipher IV */
    if (ss->so->encrypt)
    {
        dbg_err_if(cli_iv == NULL || strlen(cli_iv) != 2 * CIPHER_IV_LEN);
        dbg_err_if((c = u_hexncpy_s((char *)ss->so->cipher_iv, sizeof(ss->so->cipher_iv), cli_iv,
            strlen(cli_iv), HEXCPY_DECODE)) != CIPHER_IV_LEN);
    }

    /* set client provided mtime */
    ss->mtime = strtoul(cli_mtime, NULL, 0);

    dbg_err_if(strlen(cli_ebuf) > COOKIE_MAX_SIZE);

    /* hex decode session data */
    dbg_err_if((c = u_hexncpy_s(buf, sizeof(buf), cli_ebuf, strlen(cli_ebuf),
        HEXCPY_DECODE)) <= 0);

    /* load session data from the buffer */
    dbg_err_if(session_prv_load_from_buf(ss, buf, c));

    return 0;
err:
    return ~0;
}

static int session_client_term(session_t *ss)
{
    u_unused_args(ss);
    return 0;
}

static int session_client_remove(session_t *ss)
{
    dbg_err_if (ss == NULL);
    
    /* removes all clises-related cookies */
    dbg_err_if(session_set_cookie(ss, KL1_CLISES_DATA, NULL, 0, NULL,
        NULL, 0));
    dbg_err_if(session_set_cookie(ss, KL1_CLISES_MTIME, NULL, 0, NULL,
        NULL, 0));
    dbg_err_if(session_set_cookie(ss, KL1_CLISES_HMAC, NULL, 0, NULL,
        NULL, 0));
    dbg_err_if(session_set_cookie(ss, KL1_CLISES_IV, NULL, 0, NULL,
        NULL, 0));

    return 0;
err:
    return ~0;
}

int session_client_create(session_opt_t *so, request_t *rq, response_t *rs, 
        session_t **pss)
{
    session_t *ss = NULL;

    dbg_err_if (rq == NULL);
    dbg_err_if (rs == NULL);
    dbg_err_if (pss == NULL);
    dbg_err_if (so == NULL);

    ss = u_zalloc(sizeof(session_t));
    dbg_err_if(ss == NULL);

    ss->load = session_client_load;
    ss->save = session_client_save;
    ss->remove = session_client_remove;
    ss->term = session_client_term;
    ss->mtime = time(0);
    ss->so = so;

    dbg_err_if(session_prv_init(ss, rq, rs));

    *pss = ss;

    return 0;
err:
    if(ss)
        session_free(ss);
    return ~0;
}

/* this function will be called once by the server during startup */
int session_client_module_init(u_config_t *config, session_opt_t *so)
{
    u_config_t *c;
    const char *v;

    /* config may be NULL */
    dbg_err_if (so == NULL);
    
    /* default */
    so->hash = EVP_sha256();

    /* always enable encryption for client-side sessions */
    if(!so->encrypt)
        warn("encryption is required for client side session");
    so->encrypt = 1;

    if(config && !u_config_get_subkey(config, "client", &c))
    {
        if((v = u_config_get_subkey_value(c, "hash_function")) != NULL)
        {
            if(!strcasecmp(v, "sha256"))
                so->hash = EVP_sha256();
            else if(!strcasecmp(v, "md5"))
                so->hash = EVP_md5();
            else if(!strcasecmp(v, "sha1"))
                so->hash = EVP_sha1();
#ifdef SSL_OPENSSL
            else if(!strcasecmp(v, "ripemd160"))
                so->hash = EVP_ripemd160();
#endif
            else
                warn_err("config error: bad hash_function");
        } 
    }

#ifdef SSL_OPENSSL
    /* initialize OpenSSL HMAC stuff */
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    OSSL_PARAM params[2];
    dbg_err_if(mac == NULL);
    so->hmac_ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    dbg_err_if(so->hmac_ctx == NULL);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
        KLIN_UNCONST(EVP_MD_get0_name(so->hash)), 0);
    params[1] = OSSL_PARAM_construct_end();

    /* gen HMAC key */
    dbg_err_if(!RAND_bytes((unsigned char *)so->hmac_key, HMAC_KEY_LEN));

    /* init HMAC with our key and chose hash algorithm */
    dbg_err_if(EVP_MAC_init(so->hmac_ctx, (const unsigned char *)so->hmac_key,
        HMAC_KEY_LEN, params) != 1);
#endif


    return 0;
err:
    return ~0;
}


