/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_CODEC_CIPHER_H_
#define _KLIN_CODEC_CIPHER_H_

#include "klin_conf.h"
#include <klin/codec.h>

#ifdef SSL_ON
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif 


/* possibile values for io_gzip_create */
enum { CIPHER_ENCRYPT, CIPHER_DECRYPT };

enum {
    CODEC_CIPHER_KEY_LEN = EVP_MAX_KEY_LENGTH, 
    CODEC_CIPHER_KEY_BUFSZ = 2 * EVP_MAX_KEY_LENGTH, 
    CODEC_CIPHER_IV_LEN = EVP_MAX_IV_LENGTH,
    CODEC_CIPHER_BLOCK_LEN = EVP_MAX_BLOCK_LENGTH,
};

int codec_cipher_create(int op, const EVP_CIPHER *cipher, 
    unsigned char *key, unsigned char *iv, codec_t **pcc);

#ifdef __cplusplus
}
#endif 

#else /* SSL_ON */
/* to avoid ifdefs in local variable declaration (such vars will not be used 
   anyway because the code that use them is ifdef-out) */
enum {
    CODEC_CIPHER_KEY_LEN = 0, 
    CODEC_CIPHER_KEY_BUFSZ = 0, 
    CODEC_CIPHER_IV_LEN = 0
};

#endif /* SSL_ON */

#endif /* !_KLIN_CODEC_CIPHER_H_ */
