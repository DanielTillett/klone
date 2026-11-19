/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_CODEC_GZIP_H_
#define _KLIN_CODEC_GZIP_H_

#ifdef __cplusplus
extern "C" {
#endif 

/* the codec [un]compresses (using libz) the stream to whom it's applied */

/* possibile values for io_gzip_create: GZIP_* work on raw deflate data
   (client sessions, compressed page blocks), ZLIB_* on zlib-wrapped data,
   which is what HTTP's "Content-Encoding: deflate" means (RFC 9110
   8.4.1.2), for embedded files */
enum { GZIP_COMPRESS, GZIP_UNCOMPRESS, ZLIB_COMPRESS, ZLIB_UNCOMPRESS };

int codec_gzip_create(int operation, codec_t **pioz);

#ifdef __cplusplus
}
#endif 

#endif
