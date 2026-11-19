/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_CODEC_H_
#define _KLIN_CODEC_H_

#include <sys/types.h>
#include <stdlib.h>
#include <stdarg.h>
#include <u/libu.h>

#ifdef __cplusplus
extern "C" {
#endif 

enum { CODEC_FLUSH_COMPLETE, CODEC_FLUSH_CHUNK };

enum { CODEC_BUFSZ = 4096 };

TAILQ_HEAD(codec_chain_s, codec_s);
typedef struct codec_chain_s codec_chain_t; 

typedef ssize_t (*codec_transform_t) (struct codec_s *codec, 
    char *dst, size_t *dst_cnt, const char *src, size_t src_sz);

typedef ssize_t (*codec_flush_t) (struct codec_s *codec, 
    char *dst, size_t *dst_cnt);

typedef int (*codec_free_t) (struct codec_s *codec);

/* optional: of the next 'src_sz' input bytes, tell how many the codec would
 * output unchanged (and count them as transformed), so that the io can write
 * them out directly; 0 when they must go through transform() */
typedef size_t (*codec_passthru_t) (struct codec_s *codec, size_t src_sz);

typedef struct codec_s
{
    codec_transform_t transform;
    codec_flush_t flush;
    codec_free_t free;

    /* codec buffer */
    char cbuf[CODEC_BUFSZ];
    size_t ccount, coff;

    /* chain next & prev pointer */
    TAILQ_ENTRY(codec_s) np;

    codec_passthru_t passthru;  /* optional (NULL): see codec_passthru_t */
} codec_t;

int codec_free(codec_t *codec);

#ifdef __cplusplus
}
#endif 

#endif
