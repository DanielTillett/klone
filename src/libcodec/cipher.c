/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <u/libu.h>
#include <klin/codec.h>
#include <klin/ccipher.h>
#include <klin/utils.h>
#include <klin/crypto.h>

enum { CODEC_CIPHER_MAX_INPUT = 4096 /* max src block size for transform() */ };

struct codec_cipher_s
{
    codec_t codec;
    kc_cipher_t *cipher;        /* the cipher, encrypting or decrypting */
    char *cbuf;
    size_t coff, ccount, cbuf_size;
    int finalised;              /* the last block has been produced     */
};

typedef struct codec_cipher_s codec_cipher_t;

static void codec_cbufcpy(codec_cipher_t *cc, char *dst, size_t *dcount)
{
    size_t count;

    count = U_MIN(*dcount, cc->ccount);

    memcpy(dst, cc->cbuf + cc->coff, count);
    cc->ccount -= count;
    if(cc->ccount)
        cc->coff += count;
    else
        cc->coff = 0;
    *dcount = count;
}

static ssize_t cipher_flush(codec_t *codec, char *dst, size_t *dcount)
{
    codec_cipher_t *cc;
    size_t wr;

    dbg_err_if (codec == NULL);
    dbg_err_if (dst == NULL);
    dbg_err_if (dcount == NULL);

    cc = (codec_cipher_t*)codec;

    for(;;)
    {
        if(cc->ccount)
        {
            codec_cbufcpy(cc, dst, dcount);
            return CODEC_FLUSH_CHUNK; /* call flush again */
        }

        if(!cc->finalised)
        {
            cc->finalised = 1;  /* can be called just once */
            dbg_err_if(kc_cipher_final(cc->cipher, (unsigned char *)cc->cbuf,
                        &wr));
            cc->ccount += wr;

            if(wr)
                continue;
        }
        break;
    }

    *dcount = 0;
    return CODEC_FLUSH_COMPLETE;
err:
    return -1;
}

static ssize_t cipher_transform(codec_t *codec, char *dst, size_t *dcount, 
        const char *src, size_t src_sz)
{
    codec_cipher_t *cc;
    ssize_t c;
    size_t wr;

    dbg_err_if (codec == NULL);
    dbg_err_if (src == NULL);
    dbg_err_if (dst == NULL); 
    dbg_err_if (dcount == NULL || *dcount == 0); 
    dbg_err_if (src_sz == 0);

    cc = (codec_cipher_t*)codec;

    c = 0;
    for(;;)
    {
        if(cc->ccount)
        {
            codec_cbufcpy(cc, dst, dcount);
            return c; /* consumed */
        }

        /* the cbuf must be empty because we need the whole buffer to be sure to
           have enough output space for kc_cipher_update */

        c = U_MIN(src_sz, CODEC_CIPHER_MAX_INPUT);

        dbg_err_if(kc_cipher_update(cc->cipher, (unsigned char *)cc->cbuf, &wr,
            (const unsigned char *)src, (size_t) c));
        cc->ccount += wr;

        if(wr == 0)
        {
            *dcount = 0;
            break; /* cipher need more input to produce any output */
        }
    }

    dbg_err_if(c == 0 && *dcount == 0);
    return c;
err:
    return -1;
}

static int cipher_free(codec_t *codec)
{
    codec_cipher_t *cc;
       
    nop_return_if (codec == NULL, 0);   
        
    cc = (codec_cipher_t*)codec;

    kc_cipher_free(cc->cipher);
    U_FREE(cc->cbuf);
    U_FREE(cc);

    return 0;
}

/**
 *  \addtogroup filters
 *  \{
 */

/**
 * \brief   Create a cipher \c codec_t object 
 *
 * Create a cipher \c codec_t object at \p *pcc suitable for encryption or
 * decryption (depending on \p op).  The \p cipher, \p key and \p iv parameters
 * hold the algorithm, key and initialisation vector respectively, used for
 * the data transforms.
 *
 * \param   op      one of \c CIPHER_ENCRYPT or \c CIPHER_DECRYPT
 * \param   cipher  the algorithm, a \c KC_* cipher (klin/crypto.h)
 * \param   key     the encryption/decryption key
 * \param   iv      the initialisation vector
 * \param   pcc     the created codec as a value-result arguement
 *
 * \return \c 0 on success, \c ~0 otherwise
 */
int codec_cipher_create(int op, int cipher, unsigned char *key,
    unsigned char *iv, codec_t **pcc)
{
    codec_cipher_t *cc = NULL;

    dbg_return_if (kc_cipher_block_size(cipher) == 0, ~0);
    dbg_return_if (key == NULL, ~0);
    /* iv can be NULL */
    dbg_return_if (pcc == NULL, ~0);

    cc = u_zalloc(sizeof(codec_cipher_t));
    dbg_err_if(cc == NULL);

    cc->codec.transform = cipher_transform;
    cc->codec.flush = cipher_flush;
    cc->codec.free = cipher_free;      

    /* an update writes at most its input plus a block */
    cc->cbuf_size = CODEC_CIPHER_MAX_INPUT + kc_cipher_block_size(cipher);

    cc->cbuf = u_malloc(cc->cbuf_size);
    dbg_err_if(cc->cbuf == NULL);

    dbg_err_if(op != CIPHER_ENCRYPT && op != CIPHER_DECRYPT);
    dbg_err_if(kc_cipher_new(cipher, op == CIPHER_ENCRYPT, key, iv,
                &cc->cipher));


    *pcc = (codec_t*)cc;

    return 0;
err:
    if (cc)
        cipher_free((codec_t *)cc);
    return ~0;
}

/**
 *  \}
 */
