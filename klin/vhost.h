/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLIN_VHOST_H_
#define _KLIN_VHOST_H_

#include <u/libu.h>

#ifdef __cplusplus
extern "C" {
#endif 

/* define page list */
LIST_HEAD(vhost_list_s, vhost_s);

struct http_s;
struct klog_s;

/* the security headers of http.c's http_sec_headers table */
enum { VHOST_SEC_HEADERS = 5 };

/* follow_symlinks (doc/FILES): symbolic links in the files served by the fs
 * and cgi suppliers */
enum {
    VHOST_SYMLINKS_INSIDE,  /* followed if the target is under the root      */
    VHOST_SYMLINKS_NO,      /* never followed below the root                 */
    VHOST_SYMLINKS_YES      /* always followed                               */
};

/* a dir_alias or cgi.script_alias "src dst" value, split once */
typedef struct vhost_alias_s
{
    char *src;              /* URI prefix (NULL: malformed, never matches)   */
    size_t srclen;
    char *dst;              /* what the prefix is replaced with              */
} vhost_alias_t;

typedef struct vhost_s
{
    LIST_ENTRY(vhost_s) np; /* next & prev pointers                          */
    struct http_s *http;    /* parent http object                            */
    struct klog_s *klog;    /* vhost logging facility                        */
    u_config_t *config;     /* vhost configuration                           */
    u_config_t *al_config;  /* cached access_log config ptr                  */
    const char *host;       /* hostname                                      */
    int id;                 /* position in the vhosts list                   */

    /* cached configuration options */
    const char *server_sig; /* server signature                              */
    const char *dir_root;   /* base html directory                           */
    const char *index;      /* user-provided index page(s)                   */
    int send_enc_deflate;   /* >0 if sending deflated content is not disabled*/
    int follow_symlinks;    /* VHOST_SYMLINKS_*                              */
    int serve_files;        /* the fs supplier serves this vhost             */
    int run_cgi;            /* the cgi supplier serves this vhost            */

    /* filled on first use (see http_alias_resolv, request_load_config);
       like the fields above, read once: later changes to the configuration
       are not seen. The strings are copies owned by the vhost */
    vhost_alias_t *alias;   /* dir_alias then cgi.script_alias values        */
    size_t nalias;
    int alias_loaded;
    int rq_config_loaded;   /* the request limits below are set              */
    size_t rq_idle_timeout, rq_post_timeout, rq_post_maxsize;
    size_t rq_max_fields, rq_max_line, rq_max_header;
    char *rq_temp_dir;

    /* HTTP authentication (auth.c): the "auth" block, and the users_file
       it names (loaded when the vhost is created, owned by the vhost) */
    u_config_t *auth;
    u_config_t *auth_users;

    /* security header values sent with every response (NULL: not sent), in
       the order of http.c's http_sec_headers table */
    const char *sec_header[VHOST_SEC_HEADERS];

    /* the "routes" block (route.c), or NULL */
    u_config_t *routes;

    /* the "access" block (acl.c), or NULL */
    u_config_t *access;

    /* request validation (validate.c): the validators, owned, and whether
       there are "params" blocks */
    struct validator_s *validators;
    size_t nvalidators;
    int has_params;
} vhost_t;

typedef struct vhost_list_s vhost_list_t;

int vhost_create(vhost_t **pv);
int vhost_free(vhost_t *v);

int vhost_list_create(vhost_list_t **pvs);
int vhost_list_free(vhost_list_t *vs);
int vhost_list_add(vhost_list_t *vs, vhost_t *vhost);
vhost_t* vhost_list_get_n(vhost_list_t *vs, int n);
vhost_t* vhost_list_get(vhost_list_t *vs, const char *host);

#ifdef __cplusplus
}
#endif 

#endif
