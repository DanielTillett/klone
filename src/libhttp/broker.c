/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include <u/libu.h>
#include <klin/supplier.h>
#include <klin/broker.h>
#include <klin/request.h>
#include <klin/http.h>
#include "klin_conf.h"

enum { MAX_SUP_COUNT = 8 }; /* max number of suppliers */

extern supplier_t sup_emb;
#ifdef ENABLE_SUP_CGI
extern supplier_t sup_cgi;
#endif
#ifdef ENABLE_SUP_FS
extern supplier_t sup_fs;
#endif

struct broker_s
{
    supplier_t *sup_list[MAX_SUP_COUNT + 1];
};

int broker_is_valid_uri(broker_t *b, http_t *h, request_t *rq, const char *buf,
        size_t len)
{
    int i;
    time_t mtime;
    void *handle;

    dbg_goto_if (b == NULL, notfound);
    dbg_goto_if (buf == NULL, notfound);
    
    for(i = 0; b->sup_list[i]; ++i)
    {
        if(b->sup_list[i]->is_valid_uri(h, rq, buf, len, &handle, &mtime))
        {
            request_set_sup_info(rq, b->sup_list[i], handle, mtime);
            return 1; /* found */
        }
    }
notfound:
    return 0;
}

int broker_serve(broker_t *b, http_t *h, request_t *rq, response_t *rs)
{
    const char *file_name;
    supplier_t *sup;
    void *handle;
    time_t mtime, ims;
    int i;
    int http_status;

    dbg_err_if (b == NULL);
    dbg_err_if (rq == NULL);
    dbg_err_if (rs == NULL);

    /* get cached sup info */
    request_get_sup_info(rq, &sup, &handle, &mtime);

    if(sup == NULL)
    {
        file_name = request_get_resolved_filename(rq);
        for(i = 0; b->sup_list[i]; ++i)
        {
            if(b->sup_list[i]->is_valid_uri(h, rq, file_name, strlen(file_name),
                        &handle, &mtime) )
            {
                sup = b->sup_list[i];
                break;
            }
        }
        nop_err_if (sup == NULL);
    }

    /* If-None-Match, when sent, decides instead (the supplier checks it) */
    ims = request_get_if_modified_since(rq);
    if(ims && mtime && ims >= mtime &&
            request_get_field_value(rq, "If-None-Match") == NULL)
    {
        response_set_status(rs, HTTP_STATUS_NOT_MODIFIED); 
        dbg_err_if(response_print_header(rs));
    } else {
        dbg_err_if(sup->serve(rq, rs));

        http_status = response_get_status(rs);

        if(http_status == HTTP_STATUS_EXT_KEY_NEEDED)
            return http_status;

        /* if the user explicitly set the status from a kl1 then return 0;
           an error status of another supplier gets the server error page,
           unless the supplier has already produced its own response (e.g.
           a CGI error page, pending in the response filter) */
        if(http_status >= 400 && sup != &sup_emb &&
                !response_header_sent(rs) && !io_has_codecs(response_io(rs)))
            return http_status;
    }

    return 0; /* page successfully served */
err:
    response_set_status(rs, HTTP_STATUS_NOT_FOUND); 
    u_dbg("404, file not found: %s", request_get_filename(rq));

    return HTTP_STATUS_NOT_FOUND; /* page not found */
}

int broker_create(broker_t **pb)
{
    broker_t *b = NULL;
    int i;

    dbg_err_if (pb == NULL);

    b = u_zalloc(sizeof(broker_t));
    dbg_err_if(b == NULL);

    i = 0;
    b->sup_list[i++] = &sup_emb;

#ifdef ENABLE_SUP_CGI
    b->sup_list[i++] = &sup_cgi;
#else
#ifndef OS_WIN
    warn("CGI support disabled, build with -DKLIN_ENABLE_SUP_CGI=ON to enable it");
#endif
#endif

#ifdef ENABLE_SUP_FS
    b->sup_list[i++] = &sup_fs;
#else
    warn("File system support disabled, build with -DKLIN_ENABLE_SUP_FS=ON to enable it");
#endif

    b->sup_list[i++] = NULL;

    for(i = 0; b->sup_list[i]; ++i)
        dbg_err_if(b->sup_list[i]->init());

    *pb = b;

    return 0;
err:
    if(b)
        broker_free(b);
    return ~0;
}

int broker_free(broker_t *b)
{
    int i;

    if (b)
    {
        for(i = 0; b->sup_list[i]; ++i)
            b->sup_list[i]->term();

        U_FREE(b);
    }

    return 0;
}

