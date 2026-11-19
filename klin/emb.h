/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_EMB_H_
#define _KLIN_EMB_H_

#include "klin_conf.h"
#include <sys/stat.h>
#ifdef HAVE_STDINT
#include <stdint.h>
#endif /* HAVE_STDINT */
#include <u/libu.h>
#include <klin/klin.h>
#include <klin/dypage.h>

#ifdef __cplusplus
extern "C" {
#endif 

/* supported embedded resource type */
enum {
    ET_FILE,                /* embedded file                */
    ET_PAGE                 /* dynamic web page             */
};

/* embfile_t.comp */
enum {
    EMB_COMP_NONE = 0,      /* stored as is                                   */
    EMB_COMP_RAW = 1,       /* raw deflate (translated before Klin 4.0.0)     */
    EMB_COMP_ZLIB = 2       /* zlib: HTTP's "deflate", sent as stored         */
};

/* define resource list */
LIST_HEAD(emblist_s, embres_s);

/* common struct for embedded resources */
typedef struct embres_s
{
    LIST_ENTRY(embres_s) np;/* next & prev pointers         */
    const char *filename;   /* emb resource file name       */
    int type;               /* emb resource type (ET_*)     */
} embres_t;

/* embedded file */
typedef struct embfile_s
{
    embres_t res;           /* any emb resource must start with a embres_t    */
    size_t size;            /* size of the data block                         */
    const unsigned char *data; /* file data                                   */
    int comp;               /* how data is compressed (EMB_COMP_*)            */
    int encrypted;          /* if data is encrypted                           */
    time_t mtime;           /* time of last modification                      */
    const char *mime_type;  /* guessed mime type                              */
    size_t file_size;       /* size of the source file (not compressed)       */
    const char *etag;       /* strong ETag of the source file, quoted; NULL   */
                            /* for encrypted files (it would leak the content)*/
} embfile_t;

/* embedded dynamic klin page */
typedef struct embpage_s
{
    embres_t res;           /* any emb resource must start with a embres_t  */
    dypage_fun_t fun;
} embpage_t;

int emb_init(void);
int emb_term(void);
int emb_register(embres_t *r);
int emb_unregister(embres_t *r);
int emb_lookup(const char *filename, embres_t **pr);
int emb_count(void);
int emb_getn(size_t n, embres_t **pr);
int emb_open(const char *file, io_t **pio);

int emb_list (char ***plist);
void emb_list_free (char **list);
int emb_to_ubuf(const char *res_name, u_buf_t **pubuf);

#ifdef __cplusplus
}
#endif 

#endif
