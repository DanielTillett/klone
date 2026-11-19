/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_TRANSLAT_H_
#define _KLIN_TRANSLAT_H_

#include <u/libu.h>
#include <klin/io.h>
#include <klin/codecs.h>
#include <klin/md5.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { URI_BUFSZ = 1024, MIME_BUFSZ = 256, EMSG_BUFSZ = 512 };

typedef struct trans_info_s
{
    char file_in[U_FILENAME_MAX], file_out[U_FILENAME_MAX];
    char depend_out[U_FILENAME_MAX];
    char uri[URI_BUFSZ], mime_type[MIME_BUFSZ];
    char dfun[URI_BUFSZ];
    char key[CODEC_CIPHER_KEY_BUFSZ];
    char emsg[EMSG_BUFSZ];
    int comp;
    int encrypt;
    size_t file_size;
    time_t mtime;
    char etag[MD5_DIGEST_BUFSZ];    /* static files: MD5 of the source (hex) */
} trans_info_t;

int translate(trans_info_t*);

int translate_script_to_c(io_t *in, io_t *out, trans_info_t* ti);
int translate_opaque_to_c(io_t *in, io_t *out, trans_info_t* ti);
int translate_is_a_script(const char *filename);
int translate_makefile_filepath(const char *filepath, const char *prefix, 
    char *buf, size_t size);

#ifdef __cplusplus
}
#endif 

#endif
