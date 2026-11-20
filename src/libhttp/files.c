/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* Opening the files the fs and cgi suppliers serve (doc/FILES): a path
 * resolved for a request (dir_root or an alias target, then the normalized
 * URI) is opened under that directory with the vhost's symlink policy */

#include "klin_conf.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <u/libu.h>
#include <klin/os.h>
#include <klin/http.h>
#include <klin/request.h>
#include <klin/vhost.h>
#include "http_s.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* the directory 'fqn' was resolved under: the longest of the vhost's
 * dir_root and alias targets that is a path prefix of it. 'root' gets it
 * with the slashes http_path_join() leaves and a trailing one; returns its
 * length, 0 if there is none */
static size_t files_root(vhost_t *vhost, const char *fqn, char *root,
        size_t sz)
{
    char cand[U_FILENAME_MAX];
    const char *dir;
    size_t i, n, best = 0;

    for(i = 0; i <= vhost->nalias; ++i)
    {
        dir = (i < vhost->nalias) ? vhost->alias[i].dst : vhost->dir_root;
        if(dir == NULL || http_path_join(cand, sizeof cand, dir, ""))
            continue;
        n = strlen(cand);
        if(n > best && n < sz && strncmp(fqn, cand, n) == 0)
        {
            memcpy(root, cand, n + 1);
            best = n;
        }
    }

    return best;
}

#ifndef OS_WIN

/* directories are opened for openat() only: search permission is enough */
#if defined(O_PATH)
#define FILES_DIR_FLAGS (O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
#elif defined(O_SEARCH)
#define FILES_DIR_FLAGS (O_SEARCH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
#else
#define FILES_DIR_FLAGS (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
#endif

/* open 'rel' under the directory 'root' one segment at a time, following no
 * symbolic link: what is opened is below 'root' whatever is changed in it
 * meanwhile. Returns the descriptor, or -1 */
static int files_open_beneath(const char *root, const char *rel, int flags)
{
    char seg[U_FILENAME_MAX];
    const char *p, *e;
    size_t len;
    int dfd, nfd, fd = -1;

    if((dfd = open(root, FILES_DIR_FLAGS & ~O_NOFOLLOW)) < 0)
        return -1;

    for(p = rel; ; p = e + 1)
    {
        e = strchr(p, '/');
        len = e ? (size_t) (e - p) : strlen(p);

        /* an empty, "." or ".." segment: the path is not normalized */
        if(len == 0 || len >= sizeof seg || (p[0] == '.' &&
                    (len == 1 || (len == 2 && p[1] == '.'))))
            break;

        memcpy(seg, p, len);
        seg[len] = '\0';

        if(e == NULL)
        {
            fd = openat(dfd, seg, flags | O_NOFOLLOW | O_CLOEXEC);
            break;
        }

        nfd = openat(dfd, seg, FILES_DIR_FLAGS);
        close(dfd);
        if((dfd = nfd) < 0)
            return -1;
    }

    close(dfd);

    return fd;
}

static int files_open(int policy, const char *root, const char *fqn,
        size_t rootlen, int flags)
{
    char rroot[PATH_MAX], rfile[PATH_MAX];
    size_t n;

    switch(policy)
    {
    case VHOST_SYMLINKS_YES:
        return open(fqn, flags | O_CLOEXEC);

    case VHOST_SYMLINKS_NO:
        /* no link anywhere below the root */
        return files_open_beneath(root, fqn + rootlen, flags);

    default:
        /* links whose target is below the root (the root itself may be
           reached through links) */
        if(realpath(root, rroot) == NULL || realpath(fqn, rfile) == NULL)
            return -1;
        n = strlen(rroot);
        if(n == 1)
            n = 0;      /* the root is "/" */
        if(strncmp(rfile, rroot, n) || rfile[n] != '/' || rfile[n + 1] == 0)
            return -1;
        /* rfile has no link: one put there since realpath() is refused */
        return files_open_beneath(n ? rroot : "/", rfile + n + 1, flags);
    }
}

#else /* OS_WIN */

/* a segment Windows would read as another name or a device: a trailing dot
 * or blank, a stream (':'), a short (8.3) name or a device name */
static int files_win_bad_name(const char *seg, size_t len)
{
    static const char *dev[] = { "CON", "PRN", "AUX", "NUL", "CONIN$",
        "CONOUT$", NULL };
    size_t i, base;

    if(len == 0 || seg[len - 1] == '.' || seg[len - 1] == ' ')
        return 1;
    for(i = 0; i < len; ++i)
        if(seg[i] == ':' || (seg[i] == '~' && i + 1 < len &&
                    seg[i + 1] >= '0' && seg[i + 1] <= '9'))
            return 1;

    for(base = 0; base < len && seg[base] != '.'; ++base)
        ;
    for(i = 0; dev[i]; ++i)
        if(base == strlen(dev[i]) && !strncasecmp(seg, dev[i], base))
            return 1;
    if(base == 4 && (!strncasecmp(seg, "COM", 3) ||
                !strncasecmp(seg, "LPT", 3)) && seg[3] >= '0' && seg[3] <= '9')
        return 1;

    return 0;
}

/* no symlink, junction or other reparse point below the root, and no name
 * Windows would read differently */
static int files_open(int policy, const char *root, const char *fqn,
        size_t rootlen, int flags)
{
    char part[U_FILENAME_MAX];
    const char *p, *e;
    DWORD attr;
    size_t len;

    u_unused_args(root);

    for(p = fqn + rootlen; ; p = e + 1)
    {
        e = strchr(p, '/');
        len = e ? (size_t) (e - p) : strlen(p);
        if(files_win_bad_name(p, len))
            return -1;
        if(policy != VHOST_SYMLINKS_YES)
        {
            dbg_return_if((size_t) (p - fqn) + len >= sizeof part, -1);
            memcpy(part, fqn, (size_t) (p - fqn) + len);
            part[(p - fqn) + len] = '\0';
            attr = GetFileAttributesA(part);
            if(attr == INVALID_FILE_ATTRIBUTES ||
                    (attr & FILE_ATTRIBUTE_REPARSE_POINT))
                return -1;
        }
        if(e == NULL)
            break;
    }

    return open(fqn, flags | O_BINARY);
}

#endif /* OS_WIN */

/**
 * \brief   Open a file resolved for a request
 *
 * Open \p fqn, a path resolved for request \p rq (http_alias_resolv), with
 * the symlink policy of its virtual host (\c follow_symlinks, doc/FILES):
 * a path that is not under the vhost's dir_root or an alias target is
 * refused.
 *
 * \param h      the http object
 * \param rq     the request
 * \param fqn    the resolved path
 * \param flags  open(2) flags for the file itself
 *
 * \return the descriptor, or \c -1
 */
int http_open_file(http_t *h, request_t *rq, const char *fqn, int flags)
{
    char root[U_FILENAME_MAX];
    vhost_t *vhost;
    size_t n;

    dbg_return_if (h == NULL || rq == NULL || fqn == NULL, -1);

    dbg_return_if ((vhost = http_get_vhost(h, rq)) == NULL, -1);
    if(!vhost->alias_loaded)
        dbg_return_if (http_load_aliases(vhost), -1);

    if((n = files_root(vhost, fqn, root, sizeof root)) == 0 || fqn[n] == 0)
        return -1;

    /* the root without its trailing slash ("/" stays) */
    if(n > 1)
        root[n - 1] = '\0';

    return files_open(vhost->follow_symlinks, root, fqn, n, flags);
}
