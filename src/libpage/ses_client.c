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
#include <klin/crypto.h>

#define KL1_CLISES_DATA     "KL1_CLISES_DATA"
#define KL1_CLISES_MTIME    "KL1_CLISES_MTIME"
#define KL1_CLISES_HMAC     "KL1_CLISES_HMAC"
#define KL1_CLISES_IV       "KL1_CLISES_IV"

enum { HMAC_HEX_SIZE = 2*KC_MD_MAX + 1 };

/* calc the hmac of data+sid+mtime */
static int session_client_hmac(session_opt_t *so, char *hmac, size_t hmac_sz,
    const char *data, const char *sid, const char *mtime, const char *hex_iv)
{
    unsigned char mac[KC_MD_MAX];
    size_t mac_len;

    dbg_err_if (so == NULL);
    dbg_err_if (hmac == NULL);
    dbg_err_if (data == NULL);
    dbg_err_if (sid == NULL);
    dbg_err_if (mtime == NULL);
    /* hex_iv may be NULL */
    
    /* hmac must be at least 'KC_MD_MAX*2 + 1' (it will be hex encoded) */
    dbg_err_if(hmac_sz < KC_MD_MAX*2 + 1);

    /* calc HMAC hash of the data buf + mtime (reuse stored key and md) */
    dbg_err_if(kc_hmac_init(so->hmac));
    dbg_err_if(kc_hmac_update(so->hmac, data, strlen(data)));
    dbg_err_if(kc_hmac_update(so->hmac, sid, strlen(sid)));
    dbg_err_if(kc_hmac_update(so->hmac, mtime, strlen(mtime)));
    if(hex_iv)
        dbg_err_if(kc_hmac_update(so->hmac, hex_iv, strlen(hex_iv)));
    dbg_err_if(kc_hmac_final(so->hmac, mac, &mac_len));


    /* encode the hash */
    dbg_err_if(u_hexncpy_s(hmac, hmac_sz, (const char *)mac, mac_len, HEXCPY_ENCODE) <= 0);

    return 0;
err:
    return -1;
}

/* the format before 4.0: AES-256-CBC (the cipher codec), then an HMAC of
   the hex data, session id, mtime and IV, concatenated */
static int session_client_load_hmac(session_t *ss)
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
        !kc_memeq(hmac, cli_hmac, strlen(hmac)))
        warn_err("HMAC don't match, rejecting session data");

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

    /* load session data from the buffer (the cipher codec decrypts) */
    ss->raw = 0;
    dbg_err_if(session_prv_load_from_buf(ss, buf, c));

    return 0;
err:
    return ~0;
}

/* Client-side sessions are kept in cookies (doc/SESSIONS). The current
 * format is AES-256-GCM: KL1_CLISES_DATA is the hex of nonce, ciphertext
 * and tag, with the session id and KL1_CLISES_MTIME authenticated with it.
 * The format before 4.0 (AES-256-CBC, then an HMAC in KL1_CLISES_HMAC, the
 * IV in KL1_CLISES_IV) is still read, for this release only; saving always
 * writes the current one. */

enum { AEAD_EXTRA = KC_AEAD_NONCE + KC_AEAD_TAG, MTIME_SIZE = 32 };

/* what the tag covers besides the data */
static int session_client_aad(session_t *ss, const char *mtime, char *aad,
        size_t size)
{
    return u_snprintf(aad, size, "klin-session-2|%s|%s", ss->id, mtime);
}

static int session_client_save(session_t *ss)
{
    session_opt_t *so = ss->so;
    unsigned char sealed[COOKIE_MAX_SIZE + AEAD_EXTRA];
    char hex[2 * sizeof sealed + 1], mtime[MTIME_SIZE], aad[128];
    char *buf = NULL;
    size_t sz;
    time_t now;

    dbg_err_if (ss == NULL);

    /* the session data, compressed if asked: this driver encrypts it */
    ss->raw = 1;
    dbg_err_if(session_prv_save_to_buf(ss, &buf, &sz));
    warn_err_ifm(sz > COOKIE_MAX_SIZE,
                "session data too big for client-side sessions");

    dbg_err_sif ((now = time(NULL)) == (time_t) -1);
    dbg_err_if (u_snprintf(mtime, sizeof mtime, "%d", (ss->mtime = (int) now)));
    dbg_err_if (session_client_aad(ss, mtime, aad, sizeof aad));

    /* a fresh nonce for every save */
    dbg_err_if(kc_random(sealed, KC_AEAD_NONCE));
    dbg_err_if(kc_aead_seal(so->aead_key, sealed, aad, strlen(aad), buf, sz,
                sealed + KC_AEAD_NONCE, sealed + KC_AEAD_NONCE + sz));
    dbg_err_if(u_hexncpy_s(hex, sizeof hex, (const char *) sealed,
                sz + AEAD_EXTRA, HEXCPY_ENCODE) <= 0);

    dbg_err_if(session_set_cookie(ss, KL1_CLISES_DATA, hex, 0, NULL, NULL, 0));
    dbg_err_if(session_set_cookie(ss, KL1_CLISES_MTIME, mtime, 0, NULL,
                NULL, 0));

    /* the old format's cookies go */
    if(request_get_cookie(ss->rq, KL1_CLISES_HMAC))
        dbg_err_if(session_set_cookie(ss, KL1_CLISES_HMAC, NULL, 0, NULL,
                    NULL, 0));
    if(request_get_cookie(ss->rq, KL1_CLISES_IV))
        dbg_err_if(session_set_cookie(ss, KL1_CLISES_IV, NULL, 0, NULL,
                    NULL, 0));

    kc_cleanse(buf, sz);
    u_free(buf);

    return 0;
err:
    if(buf)
        u_free(buf);
    return ~0;
}

/* the current format: nothing is read unless the tag matches */
static int session_client_load_aead(session_t *ss, const char *data,
        const char *mtime)
{
    unsigned char sealed[COOKIE_MAX_SIZE + AEAD_EXTRA + 1];
    char plain[COOKIE_MAX_SIZE + 1], aad[128];
    ssize_t c;
    size_t n;
    int rc;

    nop_err_if(strlen(data) > 2 * (COOKIE_MAX_SIZE + AEAD_EXTRA));
    nop_err_if((c = u_hexncpy_s((char *) sealed, sizeof sealed, data,
                    strlen(data), HEXCPY_DECODE)) <= AEAD_EXTRA);
    n = (size_t) c - AEAD_EXTRA;
    nop_err_if(n > COOKIE_MAX_SIZE);

    dbg_err_if(session_client_aad(ss, mtime, aad, sizeof aad));
    nop_err_if(kc_aead_open(ss->so->aead_key, sealed, aad, strlen(aad),
                sealed + KC_AEAD_NONCE, n, sealed + KC_AEAD_NONCE + n,
                (unsigned char *) plain));

    ss->mtime = strtoul(mtime, NULL, 0);
    ss->raw = 1;
    rc = session_prv_load_from_buf(ss, plain, n);
    kc_cleanse(plain, n);

    return rc;
err:
    return ~0;
}

static int session_client_load(session_t *ss)
{
    const char *data, *mtime;

    dbg_err_if (ss == NULL);

    data = request_get_cookie(ss->rq, KL1_CLISES_DATA);
    mtime = request_get_cookie(ss->rq, KL1_CLISES_MTIME);
    nop_err_if(data == NULL || mtime == NULL);

    /* a session saved before 4.0 (remove in 5.0) */
    if(request_get_cookie(ss->rq, KL1_CLISES_HMAC))
        return session_client_load_hmac(ss);

    return session_client_load_aead(ss, data, mtime);
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
    so->hash = KC_SHA256;

    /* always enable encryption for client-side sessions */
    if(!so->encrypt)
        warn("encryption is required for client side session");
    so->encrypt = 1;

    if(config && !u_config_get_subkey(config, "client", &c))
    {
        /* sha256, md5, sha1 or ripemd160 */
        if((v = u_config_get_subkey_value(c, "hash_function")) != NULL &&
                (so->hash = kc_md_from_name(v)) == 0)
            warn_err("config error: bad hash_function");
    }

    /* gen HMAC key */
    dbg_err_if(kc_random(so->hmac_key, HMAC_KEY_LEN));

    /* HMAC with our key and the chosen hash algorithm (the format before
       4.0, read only) */
    dbg_err_if(kc_hmac_new(so->hash, so->hmac_key, HMAC_KEY_LEN, &so->hmac));

    /* the AES-256-GCM key of the current format */
    dbg_err_if(kc_random(so->aead_key, KC_AEAD_KEY));


    return 0;
err:
    return ~0;
}


