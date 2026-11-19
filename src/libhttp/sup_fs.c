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
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <klin/supplier.h>
#include <klin/io.h>
#include <klin/utils.h>

static int fs_is_valid_uri(http_t *h, request_t *rq, const char *uri, 
        size_t len, void **handle, time_t *mtime)
{
    struct stat st; 
    char fqn[U_FILENAME_MAX];

    dbg_return_if (uri == NULL, 0);
    dbg_return_if (mtime == NULL, 0);
    dbg_return_if (len + 1 > U_FILENAME_MAX, 0);

    u_unused_args(h, rq);

    memcpy(fqn, uri, len);
    fqn[len] = '\0';

    /* fqn must be already normalized */
    if(strstr(fqn, ".."))
        return 0; 

    if(stat(fqn, &st) == 0 && S_ISREG(st.st_mode))
    {
        *mtime = st.st_mtime;
        *handle = NULL;

        return 1;
    } else
        return 0;
}

static int fs_serve(request_t *rq, response_t *rs)
{
    enum { BUFSZ = 4096 };
    io_t *io = NULL, *out = NULL;
    const char *mime_type, *fqn;
    ssize_t c = 0;
    char buf[BUFSZ];
    struct stat st;
    off_t left;

    dbg_err_if (rq == NULL);
    dbg_err_if (rs == NULL);

    /* output stream */
    out = response_io(rs);
    dbg_err_if(out == NULL);

    fqn = request_get_resolved_filename(rq);

    /* open the file first so the size sent is the size of what is read */
    dbg_err_if(u_file_open(fqn, O_RDONLY, &io));
    dbg_err_if(fstat(io_fd_get_d(io), &st));
    dbg_err_if(response_set_content_length(rs, st.st_size));

    /* guess the mime type append a Content-Type field to the response*/
    mime_type = u_guess_mime_type(fqn);
    dbg_err_if(response_set_content_type(rs, mime_type));

    /* add a Last-Modified field */
    dbg_err_if(response_set_last_modified(rs, st.st_mtime));

    /* print the reponse header */
    dbg_err_if(response_print_header_to_io(rs, out));

    /* if this's a HEAD request don't print the file content */
    if(response_get_method(rs) == HM_HEAD)
    {
        io_free(io);
        return 0;
    }

    /* write out the file, exactly Content-Length bytes even if it is
       changing while being sent */
    for(left = st.st_size; left > 0; left -= c)
    {
        c = io_read(io, buf, (size_t) U_MIN((off_t) BUFSZ, left));
        if(c <= 0)
            break;
        dbg_err_if(io_write(out, buf, c) < 0);
    }

    dbg_err_if(c < 0);

    /* the file shrank: the client still waits for the missing bytes */
    if(left > 0)
        response_close_connection(rs);

    io_free(io);

    return 0;
err:
    if(io)
        io_free(io);
    return ~0;
}

static int fs_init(void)
{
    return 0;
}

static void fs_term(void)
{
    return;
}

supplier_t sup_fs = {
    "fs supplier",
    fs_init,
    fs_term,
    fs_is_valid_uri,
    fs_serve
};

