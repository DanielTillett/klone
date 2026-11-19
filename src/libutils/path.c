/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <u/libu.h>
#include <klin/emb.h>
#include <klin/utils.h>
#ifdef HAVE_STRINGS
#include <strings.h>
#endif

/**
 * \brief   Removes /./, /../ and // from the path
 * 
 * Clean ups a path removing /./, /../ and multiple consecutive
 * slashes from the given path.
 *
 * Note that the function modifies the 'path' buffer.
 *
 * \param   path        the path to normalize
 *
 * \return
 * - \c 0   successful
 * - \c ~0  error
 */
int u_uri_normalize(char *path)
{
    enum { SLASH = '/', BACKSLASH = '\\' };
    char *pp, *r, *w, *seg;
    size_t len;
    int trsl = 0; /* trailing slash */

    dbg_err_if(path == NULL);

    /* convert backslashes to slashes */
    for(pp = path; *pp; ++pp)
        if(*pp == BACKSLASH)
            *pp = SLASH;

    /* must be an absolute path (i.e. must start with a slash) */
    dbg_err_if(path[0] != SLASH);

    if(pp[-1] == SLASH)
        trsl = 1;

    /* rewrite in place: the output ('/seg' for each kept segment) is never
       longer than the input read so far */
    for(r = w = path; *r; )
    {
        while(*r == SLASH)
            ++r;    /* double slash */
        if(*r == '\0')
            break;

        for(seg = r; *r && *r != SLASH; ++r)
            ;
        len = (size_t) (r - seg);

        if(len == 1 && seg[0] == '.')
            continue; /* /./ */

        if(len == 2 && seg[0] == '.' && seg[1] == '.')
        {
            /* eat last dir */
            while(w > path && w[-1] != SLASH)
                --w;
            if(w > path)
                --w;
            continue;
        }

        *w++ = SLASH;
        memmove(w, seg, len);
        w += len;
    }

    if(w == path || trsl)
        *w++ = SLASH;
    *w = '\0';

    return 0;
err:
    return ~0;
}

/**
 *  \brief  Check where the supplied path \p fqn is located
 *
 *  \param  fqn     the fully qualified path to check
 *  \param  where   one of \c U_PATH_IN_EMBFS, \c U_PATH_IN_FS or 
 *                  \c U_PATH_NOT_FOUND
 *
 *  \return \c 0 on success, \c ~0 on error
 */ 
int u_path_where_art_thou (const char *fqn, int *where)
{
    struct stat sb;
    embres_t *dummy;

    dbg_return_if (fqn == NULL, ~0);
    dbg_return_if (where == NULL, ~0);

    /* check embfs first */
    if (emb_lookup(fqn, &dummy) == 0)
    {
        *where = U_PATH_IN_EMBFS;
        return 0;
    }

    /* then the file system */
    if (stat(fqn, &sb) == 0)
    {
        *where = U_PATH_IN_FS;
        return 0;
    }

    /* then give up */
    *where = U_PATH_NOT_FOUND;

    return 0;
}
