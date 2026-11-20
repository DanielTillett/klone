/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef SSL_ON
#include <klin/crypto.h>
#include <klin/ccipher.h>
#endif 
#include <u/libu.h>
#include <klin/session.h>
#include <klin/request.h>
#include <klin/response.h>
#include <klin/vars.h>
#include <klin/utils.h>
#include <klin/ses_prv.h>
#include <klin/codecs.h>

enum {
    DEFAULT_SESSION_EXPIRATION = 60*20,     /* idle: 20 minutes          */
    DEFAULT_SESSION_LIFETIME = 60*60*8,     /* absolute: 8 hours         */
    CSRF_TOKEN_BYTES = 32
};

/* variables the session keeps for itself (doc/SESSIONS) */
static const char CREATED_VAR[] = "KLIN_SESSION_CREATED";
static const char CSRF_VAR[] = "KLIN_CSRF_TOKEN";
static const char SID_NAME[] = "klin_sid";
/* the cookie's name before KLone was renamed Klin: still read for one
   release, so an upgrade does not log every user out */
static const char SID_NAME_OLD[] = "klone_sid";

/* a page written before KLone was renamed Klin may set the cipher key under
   its old name: give it the new one, so it is saved and found as the key */
static void session_adopt_old_key_var(session_t *ss)
{
    var_t *v;

    if((v = vars_get(ss->vars, SESSION_KEY_VAR_OLD)) == NULL)
        return;

    if(vars_get(ss->vars, SESSION_KEY_VAR) == NULL)
        dbg_if(var_set_name(v, SESSION_KEY_VAR));
    else if(!vars_del(ss->vars, v))     /* the new name wins */
        var_free(v);
}

int session_set_cookie(session_t *ss, const char *name, const char *value,
    time_t expire, const char *path, const char *domain, int secure)
{
    int flags = RESPONSE_COOKIE_HTTPONLY | RESPONSE_COOKIE_SAMESITE_LAX;
    dbg_return_if(ss == NULL, ~0);
    if (secure || io_is_secure(request_io(ss->rq)))
        flags |= RESPONSE_COOKIE_SECURE;
    return response_set_cookie_ex(ss->rs, name, value, expire,
        path ? path : "/", domain, flags);
}


struct save_cb_params_s
{
    session_t *ss;
    io_t *io;
};

typedef struct save_cb_params_s save_cb_params_t;

int session_module_term(session_opt_t *so)
{
    if (so)
        dbg_if(atoms_free(so->atoms));
#ifdef SSL_ON
    if (so)
        kc_hmac_free(so->hmac);
#endif
    U_FREE(so);

    return 0;
}

/* a session time setting: minutes ("20"), or seconds ("90s"); 0 is
   allowed (no limit, where that means anything) */
static int session_conf_time(const char *v, int *psecs)
{
    char *end;
    long n;

    dbg_return_if (v == NULL || psecs == NULL, ~0);

    n = strtol(v, &end, 10);
    nop_return_if (end == v || n < 0 || n > 60L*24*366, ~0);
    if(*end == 's' || *end == 'S')
        ++end;
    else
        n *= 60;
    nop_return_if (*end != '\0', ~0);
    *psecs = (int) n;

    return 0;
}

int session_module_init(u_config_t *config, session_opt_t **pso)
{
    int iv;
    session_opt_t *so = NULL;
    u_config_t *c = NULL;
    const char *v;

    dbg_err_if (config == NULL);
    dbg_err_if (pso == NULL);

    dbg_err_sif ((so = u_zalloc(sizeof(session_opt_t))) == NULL);

    /* defaults values */
    so->type = SESSION_TYPE_FILE;
    so->max_age = DEFAULT_SESSION_EXPIRATION;
    so->max_life = DEFAULT_SESSION_LIFETIME;
    so->compress = 0;
    so->encrypt = 0;
    (void) u_strlcpy(so->name, SID_NAME, sizeof so->name);

    /* In case no 'session' subsection is found, defaults will be used. */

    if(!u_config_get_subkey(config, "session", &c))
    {
        /* set session type */
        if((v = u_config_get_subkey_value(c, "type")) != NULL)
        {
            if(!strcasecmp(v, "memory"))
                so->type = SESSION_TYPE_MEMORY;
            else if(!strcasecmp(v, "file"))
                so->type = SESSION_TYPE_FILE;
#ifdef SSL_ON
            else if(!strcasecmp(v, "client"))
                so->type = SESSION_TYPE_CLIENT;
#endif
            else
               warn_err("config error: bad session type \'%s\'", v);
        }

        /* idle timeout (max_age is its older name) and absolute timeout:
           minutes, or seconds with an 's' */
        if((v = u_config_get_subkey_value(c, "idle_timeout")) != NULL ||
                (v = u_config_get_subkey_value(c, "max_age")) != NULL)
        {
            warn_err_ifm (session_conf_time(v, &iv) || iv == 0,
                    "config error: bad session idle_timeout \'%s\'", v);
            so->max_age = iv;
        }
        if((v = u_config_get_subkey_value(c, "absolute_timeout")) != NULL)
            warn_err_ifm (session_conf_time(v, &so->max_life),
                    "config error: bad session absolute_timeout \'%s\'", v);

        /* set compression flag */
        dbg_err_if(u_config_get_subkey_value_b(c, "compress", 0,
            &so->compress));

        /* set encryption flag */
        dbg_err_if(u_config_get_subkey_value_b(c, "encrypt", 0, &so->encrypt));

        /* set cookie name */
        if ((v = u_config_get_subkey_value(c, "sid_name")) != NULL)
            dbg_err_if (u_strlcpy(so->name, v, sizeof so->name));

#ifndef HAVE_LIBZ
        if(so->compress)
            warn_err("config error: compression is enabled but libz is not "
                     "linked");
#endif

#ifndef SSL_ON
        if(so->encrypt)
            warn_err("config error: encryption is enabled but no SSL "
                     "lib is linked");
#else

        /* the cipher, the random key and IV */
        so->cipher = KC_AES_256_CBC;

        /* key and iv for client-side session */
        dbg_err_if(kc_random(so->cipher_key, CIPHER_KEY_LEN));
        dbg_err_if(kc_random(so->cipher_iv, CIPHER_IV_LEN));

        /* create a random key and iv to crypt the SESSION_KEY_VAR variable */
        dbg_err_if(kc_random(so->session_key, CIPHER_KEY_LEN));
        dbg_err_if(kc_random(so->session_iv, CIPHER_IV_LEN));


#endif
    } /* if "session" exists */

    /* per-type configuration init */
    if(so->type == SESSION_TYPE_MEMORY)
        warn_err_ifm(session_mem_module_init(c, so), 
            "in-memory session engine init error");
    else if(so->type == SESSION_TYPE_FILE)
        warn_err_ifm(session_file_module_init(c, so), 
            "file session engine init error");
#ifdef SSL_ON
    else if(so->type == SESSION_TYPE_CLIENT)
        warn_err_ifm(session_client_module_init(c, so),
            "client-side session engine init error");
#endif

    *pso = so;

    return 0;
err:
    session_module_term(so);
    return ~0;
}

int session_prv_calc_maxsize(var_t *v, void *p)
{
    const char *value = NULL;
    size_t *psz = (size_t*)p;

    dbg_err_if (v == NULL);
    dbg_err_if (var_get_name(v) == NULL);
    dbg_err_if (psz == NULL);

#ifdef SSL_ON
    if(*psz == 0)
    {   /* a block plus the padding block */
        *psz = CODEC_CIPHER_BLOCK_LEN * 2;
    }
#endif

    /* name= */
    *psz += 3 * strlen(var_get_name(v)) + 3;

    /* value */
    if((value = var_get_value(v)) != NULL)
        *psz += 3 * strlen(value) + 1; /* worse case (i.e. longest string) */

    return 0;
err:
    return ~0;
}

int session_prv_load_from_buf(session_t *ss, char *buf, size_t size)
{
    io_t *io = NULL;

    dbg_err_if (ss == NULL);
    dbg_err_if (buf == NULL);

    /* build an io_t around the buffer */
    dbg_err_if(io_mem_create(buf, size, 0, &io));

    /* load data */
    dbg_err_if(session_prv_load_from_io(ss, io));

    io_free(io);

    return 0;
err:
    if(io)
        io_free(io);
    return ~0;
}

int session_prv_save_to_buf(session_t *ss, char **pbuf, size_t *psz)
{
    io_t *io = NULL;
    char *buf = NULL;
    size_t sz = 0;

    dbg_err_if (ss == NULL);
    dbg_err_if (pbuf == NULL);
    dbg_err_if (psz == NULL);
 
    /* calc the maximum session data size (exact calc requires url encoding and
       codec transformation knowledge) */
    vars_foreach(ss->vars, session_prv_calc_maxsize, (void*)&sz);

    /* alloc a big-enough block to save the session data */
    buf = u_malloc(sz);
    dbg_err_if(buf == NULL);

    /* create a big-enough in-memory io object */
    dbg_err_if(io_mem_create(buf, sz, 0, &io));

    /* save the session to the in-memory io */
    dbg_err_if(session_prv_save_to_io(ss, io));

    /* remove all codecs to get the right size of 'buf'. we need to remove 
       the codecs because some of them buffer data until last codec->flush() 
       is called (and it's not possible to flush codecs without removing them */
    dbg_err_if(io_codecs_remove(io));

    /* get the number of bytes written to the io (so to 'buf') */
    sz = io_tell(io);

    io_free(io);
    io = NULL;

    *pbuf = buf;
    *psz = sz;

    return 0;
err:
    if(io)
        io_free(io);
    U_FREE(buf);
    return ~0;
}

/* Supplied 'id' must be SESSION_ID_LENGTH long and made of hex digits only. */
static int session_is_good_id(const char *id)
{
    const char *p;

    dbg_return_if (id == NULL, 0);
    dbg_return_if (strlen(id) != SESSION_ID_LENGTH, 0);

    for (p = id; *p != '\0'; ++p)
    {
        if (!isxdigit((unsigned char) *p))
            return 0;
    }

    return 1; /* good */
}

static int session_set_filename(session_t *ss)
{
    const char *a = NULL;
    char old[U_FILENAME_MAX];
    struct stat st;

    dbg_return_if (ss->id[0] == '\0', ~0);

    dbg_err_if((a = request_get_addr(ss->rq)) == NULL);

    dbg_err_if(u_path_snprintf(ss->filename, U_FILENAME_MAX,
            U_PATH_SEPARATOR, "%s/klin_sess_%s_%s", ss->so->path, ss->id, a));

    /* a session file saved before KLone was renamed Klin: take it over
       under the new name, so loading, saving and removal all use one file */
    if(ss->so->type == SESSION_TYPE_FILE && stat(ss->filename, &st) != 0 &&
            !u_path_snprintf(old, U_FILENAME_MAX, U_PATH_SEPARATOR,
                "%s/klone_sess_%s_%s", ss->so->path, ss->id, a) &&
            stat(old, &st) == 0)
        dbg_if(rename(old, ss->filename));

    return 0;
err:
    return ~0;
}

static int session_gen_id(session_t *ss)
{
    unsigned char random[SESSION_ID_LENGTH / 2];

    dbg_err_if (ss == NULL);

    /* Initialize sid to empty string. */
    ss->id[0] = '\0';

    dbg_err_if(u_random_bytes(random, sizeof(random)));
    u_tohex(ss->id, (const char *)random, sizeof(random));

    /* Remove previous SID, if any. */ 
    dbg_err_if (session_set_cookie(ss, ss->so->name, NULL,
                0, NULL, NULL, 0));

    /* Set the cookie ID. */
    dbg_err_if (session_set_cookie(ss, ss->so->name, ss->id,
                0, NULL, NULL, 0));

    return 0;
err:
    return ~0;
}

int session_prv_set_id(session_t *ss, const char *sid)
{
    dbg_return_if (ss == NULL, ~0);

    /* set or generate a session id */
    if (sid && session_is_good_id(sid))
        dbg_err_if (u_snprintf(ss->id, sizeof ss->id, "%s", sid));
    else
        dbg_err_if (session_gen_id(ss));

    /* set the filename accordingly */
    dbg_err_if (session_set_filename(ss));

    return 0;
err:
    return ~0;
}

int session_priv_set_id(session_t *ss, const char *sid)
{
    return session_prv_set_id(ss, sid); /* backward compatibility */
}

int session_load(session_t *ss)
{
    dbg_return_if (ss == NULL, ~0);
    dbg_return_if (ss->load == NULL, ~0);

    return ss->load(ss);
}

/* does the session hold anything but the variables it keeps for itself? */
static int session_has_user_vars(session_t *ss)
{
    var_t *v;
    size_t i;

    for (i = 0; (v = vars_getn(ss->vars, i)) != NULL; ++i)
        if (strcmp(var_get_name(v), CREATED_VAR) &&
                strcmp(var_get_name(v), CSRF_VAR))
            return 1;

    return 0;
}

static int session_set_created(session_t *ss)
{
    char now[32];

    dbg_err_if (u_snprintf(now, sizeof now, "%lld", (long long) time(NULL)));
    dbg_err_if (session_set(ss, CREATED_VAR, now));

    return 0;
err:
    return ~0;
}

/* past the absolute timeout? (a session saved before there was one starts
   counting now) */
static int session_too_old(session_t *ss)
{
    const char *v = session_get(ss, CREATED_VAR);

    if (ss->so->max_life == 0)
        return 0;
    if (v == NULL)
    {
        dbg_if (session_set_created(ss));
        return 0;
    }

    return (long long) time(NULL) - atoll(v) > ss->so->max_life;
}

/* drop the session id: the next save draws a new one */
static void session_forget(session_t *ss)
{
    (void) session_clean(ss);
    ss->id[0] = '\0';
    ss->filename[0] = '\0';
}

/* an expired session: its stored copy and cookie go, and the request may
   start a new one */
static void session_expire(session_t *ss)
{
    u_dbg("session %s expired", ss->id);
    (void) session_clean(ss);
    (void) ss->remove(ss);
    (void) session_set_cookie(ss, ss->so->name, NULL, 0, NULL, NULL, 0);
    session_forget(ss);
}

int session_save(session_t *ss)
{
    dbg_return_if (ss == NULL, ~0);
    dbg_return_if (ss->save == NULL, ~0);

    /* No vars set: if cookie empty it's a no-op, otherwise remove stored
     * cookies. */
    if (!session_has_user_vars(ss))
        return (ss->id[0] == '\0') ? 0 : session_remove(ss);

    /* the start of the absolute timeout */
    if (session_get(ss, CREATED_VAR) == NULL)
        dbg_err_if (session_set_created(ss));

    /* new user, need to save some vars */
    if (ss->id[0] == '\0')
    {
        /* generate a new SID and set session filename accordingly */
        dbg_err_if (session_prv_set_id(ss, NULL)); 
    }

    return ss->save(ss);
err:
    return ~0;
}

int session_remove(session_t *ss)
{
    dbg_return_if (ss == NULL, ~0);
    dbg_return_if (ss->remove == NULL, ~0);

    /* remove the cookie */
    session_set_cookie(ss, ss->so->name, NULL, 0, NULL, NULL, 0);

    ss->removed = 1;

    return ss->remove(ss);
}

int session_prv_init(session_t *ss, request_t *rq, response_t *rs)
{
    const char *sid;

    dbg_err_if (ss == NULL);
    dbg_err_if (rq == NULL);
    dbg_err_if (rs == NULL);
    
    dbg_err_if(vars_create(&ss->vars));

    ss->rq = rq;
    ss->rs = rs;

    /* if the client has a SID set and it's a good one then use it */
    sid = request_get_cookie(ss->rq, ss->so->name);
    if(sid == NULL && !strcmp(ss->so->name, SID_NAME))
        sid = request_get_cookie(ss->rq, SID_NAME_OLD);
    if(sid)
        dbg_err_if(session_prv_set_id(ss, sid));

    return 0;
err:
    return ~0;
}

int session_prv_load_from_io(session_t *ss, io_t *io)
{
    u_string_t *line = NULL;
    var_t *v = NULL;
    codec_t *unzip = NULL, *decrypt = NULL;
    unsigned char key[CODEC_CIPHER_KEY_BUFSZ];
    size_t ksz;

    dbg_return_if (ss == NULL, ~0);
    dbg_return_if (io == NULL, ~0);

#ifdef SSL_ON
    if(ss->so->encrypt && !ss->raw)
    {
        dbg_err_if(codec_cipher_create(CIPHER_DECRYPT, ss->so->cipher, 
            ss->so->cipher_key, ss->so->cipher_iv, &decrypt)); 
        dbg_err_if(io_codec_add_tail(io, decrypt));
        decrypt = NULL; /* io_t owns it after io_codec_add_tail */
    }
#else
    u_unused_args(key, ksz);
#endif

#ifdef HAVE_LIBZ
    if(ss->so->compress)
    {
        dbg_err_if(codec_gzip_create(GZIP_UNCOMPRESS, &unzip));
        dbg_err_if(io_codec_add_tail(io, unzip));
        unzip = NULL; /* io_t owns it after io_codec_add_tail */
    }
#endif

    dbg_err_if(u_string_create(NULL, 0, &line));

    while(u_getline(io, line) == 0)
    {
        if(u_string_len(line))
        {
            dbg_err_if(vars_add_urlvar(ss->vars, u_string_c(line), &v));

            /* a session saved before KLone was renamed Klin */
            if(!strcmp(var_get_name(v), SESSION_KEY_VAR_OLD))
                dbg_err_if(var_set_name(v, SESSION_KEY_VAR));

#ifdef SSL_ON
            if(!strcmp(var_get_name(v), SESSION_KEY_VAR))
            {
                /* decrypt key and save it to key */
                memset(key, 0, sizeof(key));
				ksz = sizeof(key);
                dbg_ifb(u_cipher_decrypt(KC_AES_256_CBC, ss->so->session_key,
                    ss->so->session_iv, (char *)key, &ksz, 
                    var_get_value(v), var_get_value_size(v)))
                {
                    /* drop the key that does not decrypt (vars_del() only
                       unlinks it: found by fuzzing, it leaked) */
                    if(vars_del(ss->vars, v) == 0)
                        var_free(v);
                    v = NULL;
                } else {
                    /* save it to the var list */
                    dbg_err_if(var_set_bin_value(v, key, ksz));
                }

            }
#endif
        }
    }

    /* remove set codecs and flush */
    io_codecs_remove(io);

    u_string_free(line);

    return 0;
err:
    if(io)
        io_codecs_remove(io);
    if(decrypt)
        codec_free(decrypt);
    if(unzip)
        codec_free(unzip);
    if(line)
        u_string_free(line);
    return ~0;
}

int session_free(session_t *ss)
{
    if (ss)
    { 
        if(!ss->removed)
            dbg_if(session_save(ss));

        /* driver cleanup */
        dbg_if(ss->term(ss));

        if(ss->vars)
            vars_free(ss->vars);

        U_FREE(ss);
    }

    return 0;
}

/** 
 * \ingroup session
 * \brief   Get session variables
 *  
 * Return a vars_t containing the session variables.
 *
 * \param ss  session object
 *  
 * \return the variables' list of the given \p ss (may be \c NULL)
 */
vars_t *session_get_vars(session_t *ss)
{
    dbg_return_if (ss == NULL, NULL);

    return ss->vars;
}

/**
 * \ingroup session
 * \brief   Get session variable with given name
 *
 * Return a string representation of variable in \p ss with given \p name.
 *
 * \param ss    session object
 * \param name  session variable name
 * 
 * \return the variable value corresponding to the given \p name (may be 
 *         \c NULL)
 */
const char *session_get(session_t *ss, const char *name)
{
    var_t *v;

    dbg_return_if (ss == NULL, NULL);
    dbg_return_if (name == NULL, NULL);
    
    v = vars_get(ss->vars, name);
    return v ? var_get_value(v): NULL;
}

/** 
 * \ingroup session
 * \brief   Get session id string
 *  
 * Return a string carrying the session id.
 *
 * \param ss  session object
 *  
 * \return a string carrying the session id of the given \p ss (may be \c NULL)
 */
const char *session_get_id (session_t *ss)
{
    dbg_return_if (ss == NULL, NULL);

    return ss->id;
}

/** 
 * \ingroup session
 * \brief   Set session variable with given name to a value
 *  
 * Put variable with \p name and \p value into \p ss.
 *
 * \param ss     session object
 * \param name   session variable name
 * \param value  session variable value
 *  
 * \return \c 0 if successful, non-zero on error
 */
int session_set(session_t *ss, const char *name, const char *value)
{
    var_t *v = NULL;

    dbg_err_if (ss == NULL);
    dbg_err_if (name == NULL);
    dbg_err_if (value == NULL);
    dbg_err_if (strlen(name) == 0);

    if((v = vars_get(ss->vars, name)) == NULL)
    {
        /* add a new session variable */
        dbg_err_if(var_create(name, value, &v));

        dbg_err_if(vars_add(ss->vars, v));
    } else {
        /* update an existing var */
        dbg_ifb(var_set_value(v, value))
            return ~0;
    }

    return 0;
err:
    if(v)
        var_free(v);
    return ~0;
}

/** 
 * \ingroup session
 * \brief   Get the amount of time a session has been inactive
 *  
 * Return the number of seconds since the session was last modified.
 *
 * \param ss  session object
 *  
 * \return
 *  - the number of seconds since last modification
 *  - \c -1 on error
 */
int session_age(session_t *ss)
{
    time_t now;

    dbg_return_if (ss == NULL, -1);

    now = time(0);

    /* ss->mtime must has been set into session_X_create funcs */
    return (int)(now - ss->mtime); /* in seconds */
}

/** 
 * \ingroup session
 * \brief   Remove all session variables
 *  
 * Remove all session variables from \p ss.
 *
 * \param ss  session object
 *  
 * \return \c 0 if successful, non-zero on error
 */
int session_clean(session_t *ss)
{
    var_t *v = NULL;

    dbg_err_if (ss == NULL);

    while((v = vars_getn(ss->vars, 0)) != NULL)
    {
        dbg_err_if(vars_del(ss->vars, v));
        var_free(v);
    }

    return 0;
err:
    return ~0;
}

/**
 * \ingroup session
 * \brief   Delete session variable given a name
 *  
 * Delete session variable \p name in \p ss.
 *
 * \param ss    session object
 * \param name  session variable name
 *  
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int session_del(session_t *ss, const char *name)
{
    var_t *v = NULL;

    dbg_err_if (ss == NULL);
    dbg_err_if (name == NULL);
    
    dbg_err_if((v = vars_get(ss->vars, name)) == NULL);
    dbg_err_if(vars_del(ss->vars, v));
    var_free(v);

    return 0;
err:
    return ~0;
}

#ifdef SSL_ON
/**
 * \ingroup session
 * \brief   Set the key used to decrypt encrypted embedded content resources
 *  
 * The provided key will be stored in the user session and it will be used to
 * decrypt all embedded encrypted content.
 *
 * The server will return HTTP status 430 to notify the client that a key is
 * needed. Use "error.430" in the config file to create a page the user will
 * use to provide the key.
 *
 * \param ss    session object
 * \param data  key binary buffer
 * \param sz    key size
 *  
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int session_set_cipher_key(session_t *ss, const char *data, size_t sz)
{
    var_t *v = NULL;

    dbg_err_if(ss == NULL);
    dbg_err_if(ss->vars == NULL);
    dbg_err_if(data == NULL);
    dbg_err_if(sz == 0);

    /* remove the old key if it has been set */
    if((v = vars_get(ss->vars, SESSION_KEY_VAR)) != NULL)
    {
        dbg_err_if(vars_del(ss->vars, v));
        v = NULL;
    }

    /* may contain \0 values; treat it as opaque binary data */
    dbg_err_if(var_bin_create(SESSION_KEY_VAR, (const unsigned char *)data,
        sz, &v));

    dbg_err_if(vars_add(ss->vars, v));
    v = NULL;

    return 0;
err:
    if(v)
        var_free(v);
    return ~0;
}

/**
 * \ingroup session
 * \brief   Return the key used to decrypt encrypted embedded content resources
 *  
 * Copies the key set with session_set_cipher_key to the given buffer.
 *
 * \p psz is a value-result and must be set to the size of the buffer before
 * calling the function; on return will contain the size of the key copied to
 * \p buf.
 *
 * \param ss    session object
 * \param buf   output buffer
 * \param psz   value-result; contains the size if \p buf on entrance and the written bytes on exit
 *  
 * \return
 *  - \c 0  if successful
 *  - \c ~0 on error
 */
int session_get_cipher_key(session_t *ss, char *buf, size_t *psz)
{
    var_t *v = NULL;
    size_t vsize;

    dbg_err_if(ss == NULL);
    dbg_err_if(ss->vars == NULL);
    dbg_err_if(buf == NULL);
    dbg_err_if(psz == 0);
    dbg_err_if(*psz == 0);

    session_adopt_old_key_var(ss);

    nop_err_if((v = vars_get(ss->vars, SESSION_KEY_VAR)) == NULL);

    vsize = var_get_value_size(v);

    dbg_err_if(vsize >= *psz);

    memcpy(buf, var_get_value(v), vsize);

    *psz = vsize;

    return 0;
err:
    /* v (if any) belongs to ss->vars */
    return ~0;
}

#endif

int session_prv_save_to_io(session_t *ss, io_t *out)
{
    save_cb_params_t prm; 
    codec_t *zip = NULL, *cencrypt = NULL;

    dbg_err_if (ss == NULL);
    dbg_err_if (out == NULL);

#ifdef HAVE_LIBZ
    if(ss->so->compress)
    {
        dbg_err_if(codec_gzip_create(GZIP_COMPRESS, &zip));
        dbg_err_if(io_codec_add_tail(out, zip));
        zip = NULL; /* io_t owns it after io_codec_add_tail */
    }
#endif

#ifdef SSL_ON
    if(ss->so->encrypt && !ss->raw)
    {
        dbg_err_if(codec_cipher_create(CIPHER_ENCRYPT, ss->so->cipher, 
            ss->so->cipher_key, ss->so->cipher_iv, &cencrypt));
        dbg_err_if(io_codec_add_tail(out, cencrypt));
        cencrypt = NULL; /* io_t owns it after io_codec_add_tail */
    }
#endif

    /* pass io and session pointers to the callback function */
    prm.io = out;
    prm.ss = ss;

    /* so a key set by an older page is saved (encrypted) as the key */
    session_adopt_old_key_var(ss);

    vars_foreach(ss->vars, session_prv_save_var, (void*)&prm);

    /* remove all codecs and flush */
    io_codecs_remove(out);

    return 0;
err:
    if(out)
        io_codecs_remove(out);
    if(zip)
        codec_free(zip);
    if(cencrypt)
        codec_free(cencrypt);
    return ~0;
}

/* save a var_t (text or binary) to the session io_t */
int session_prv_save_var(var_t *v, void *vp)
{
    enum { NAMESZ = 256, VALSZ = 4096 };
    char sname[NAMESZ], svalue[VALSZ];
    char *uname = sname, *uvalue = svalue;
    save_cb_params_t *pprm = (save_cb_params_t*)vp;
    /* encrypted key buffer */
    unsigned char ekey[CODEC_CIPHER_KEY_BUFSZ]; /* key + padding block */
    unsigned char pkey[CODEC_CIPHER_KEY_BUFSZ];
    size_t nsz, vsz, eksz, pksz;
    int rc = ~0;

    dbg_err_if (v == NULL);
    /* dbg_err_if (vp == NULL); */

    memset(sname, 0, NAMESZ);
    memset(svalue, 0, VALSZ);

    /* buffers must be at least three times the src data to URL-encode  */
    nsz = 1 + 3 * strlen(var_get_name(v));  /* name buffer size  */
    vsz = 1 + 3 * var_get_value_size(v);    /* value buffer size */

#ifdef SSL_ON
    vsz += CODEC_CIPHER_BLOCK_LEN; /* encryption may enlarge the content up 
                                       to CODEC_CIPHER_BLOCK_LEN -1         */
#else
    u_unused_args(ekey, eksz, pkey, pksz);
#endif

    /* if the buffer on the stack is too small alloc a bigger one */
    if(NAMESZ <= nsz)
        dbg_err_if((uname = u_zalloc(nsz)) == NULL);

    /* url encode name */
    dbg_err_if(u_urlncpy_s(uname, nsz, var_get_name(v), strlen(var_get_name(v)),
        URLCPY_ENCODE) <= 0);

    if(var_get_value(v))
    {
        /* if the buffer on the stack is too small alloc a bigger one */
        if(VALSZ <= vsz)
            dbg_err_if((uvalue = u_zalloc(vsz)) == NULL);

#ifdef SSL_ON
        if(!strcmp(var_get_name(v), SESSION_KEY_VAR))
        {
			memset(pkey, 0, sizeof(pkey)); /* plain text key */
			memset(ekey, 0, sizeof(ekey)); /* encrypted text key */

			/* copy the actual key to a zero-ed buffer of size key (i.e. if the
			 * key is shorted then the buffer the trailing bytes will be 0s */
			pksz = var_get_value_size(v);

            err_err_ifm(pksz != CODEC_CIPHER_KEY_LEN,
                    "bad encryption key; it must be %u bytes long",
                    CODEC_CIPHER_KEY_LEN);

			memcpy(pkey, var_get_value(v), pksz);

			eksz = sizeof(ekey);;

            /* encrypt the key and save it to ekey */
            dbg_err_if(u_cipher_encrypt(KC_AES_256_CBC, 
                pprm->ss->so->session_key, pprm->ss->so->session_iv, 
                (char *)ekey, &eksz, (const char *)pkey, pksz));

            /* save it to the var list */
            dbg_err_if(var_set_bin_value(v, ekey, eksz));
        }
#endif

        dbg_err_if(u_urlncpy_s(uvalue, vsz, var_get_value(v), var_get_value_size(v),
            URLCPY_ENCODE) <= 0);

        dbg_err_if(io_printf(pprm->io, "%s=%s\n", uname, uvalue) < 0);
    } else 
        dbg_err_if(io_printf(pprm->io, "%s=\n", uname) < 0);

    rc = 0; /* success */
err:
    /* free heap buffers */
    if(uname && uname != sname)
        u_free(uname);

    if(uvalue && uvalue != svalue)
        u_free(uvalue);

    return rc;
}

/**
 * \ingroup session
 * \brief   Give the session a new id
 *
 * The data is kept, the copy stored under the old id is removed, and the
 * absolute timeout starts again. Call it when a user logs in and at any
 * change of privilege, so that an id seen or set before (session
 * fixation) is worth nothing after; and before the page prints anything,
 * as the new id goes out in a cookie.
 *
 * \param ss  session object
 *
 * \return \c 0 if successful, non-zero on error
 */
int session_regenerate_id(session_t *ss)
{
    dbg_return_if (ss == NULL, ~0);

    if (ss->id[0] != '\0')
        (void) ss->remove(ss);
    ss->removed = 0;

    dbg_err_if (session_gen_id(ss));
    dbg_err_if (session_set_filename(ss));
    dbg_err_if (session_set_created(ss));

    return 0;
err:
    return ~0;
}

/**
 * \ingroup session
 * \brief   The session's CSRF token
 *
 * A random token kept in the session (made on first use): put it in each
 * form (a hidden "csrf_token" field) or send it as an X-CSRF-Token header,
 * and check requests with session_csrf_check().
 *
 * \param ss  session object
 *
 * \return the token (64 hex digits), or \c NULL on error
 */
const char *session_csrf_token(session_t *ss)
{
    unsigned char raw[CSRF_TOKEN_BYTES];
    char hex[2 * CSRF_TOKEN_BYTES + 1];
    const char *t;

    dbg_return_if (ss == NULL, NULL);

    if ((t = session_get(ss, CSRF_VAR)) != NULL)
        return t;

    dbg_err_if (u_random_bytes(raw, sizeof raw));
    dbg_err_if (u_hexncpy_s(hex, sizeof hex, (const char *) raw, sizeof raw,
                HEXCPY_ENCODE) <= 0);
    dbg_err_if (session_set(ss, CSRF_VAR, hex));

    return session_get(ss, CSRF_VAR);
err:
    return NULL;
}

/**
 * \ingroup session
 * \brief   Check a request's CSRF token
 *
 * GET and HEAD requests (which must change nothing) pass. Any other must
 * carry the session's token (session_csrf_token()) in an X-CSRF-Token
 * header field or a csrf_token argument.
 *
 * \param ss  session object
 * \param rq  the request
 *
 * \return \c 0 if the request may go ahead, non-zero otherwise (answer
 *         403)
 */
int session_csrf_check(session_t *ss, request_t *rq)
{
    const char *want, *got;
    size_t n;

    dbg_return_if (ss == NULL || rq == NULL, ~0);

    if (request_get_method(rq) == HM_GET || request_get_method(rq) == HM_HEAD)
        return 0;

    nop_return_if ((want = session_get(ss, CSRF_VAR)) == NULL, ~0);
    if ((got = request_get_field_value(rq, "X-CSRF-Token")) == NULL)
        got = request_get_arg(rq, "csrf_token");
    nop_return_if (got == NULL, ~0);

    n = strlen(want);
    nop_return_if (strlen(got) != n || !kc_memeq(want, got, n), ~0);

    return 0;
}

int session_create(session_opt_t *so, request_t *rq, response_t *rs,
    session_t **pss)
{
    session_t *ss = NULL;

    dbg_err_if (so == NULL);
    dbg_err_if (rq == NULL);
    dbg_err_if (rs == NULL);
    dbg_err_if (pss == NULL);

    switch(so->type)
    {
    case SESSION_TYPE_FILE:
        dbg_err_if(session_file_create(so, rq, rs, &ss));
        break;
    case SESSION_TYPE_MEMORY:
        dbg_err_if(session_mem_create(so, rq, rs, &ss));
        break;
#ifdef SSL_ON
    case SESSION_TYPE_CLIENT:
        dbg_err_if(session_client_create(so, rq, rs, &ss));
        break;
#endif
    default:
        warn_err("bad session type");
    }

    if(ss->id[0] != '\0')
    {
        /* an id that names no stored session (one a client chose, say) is
           not taken on, against session fixation: a new one is drawn when
           there is something to save */
        if (session_load(ss) || !session_has_user_vars(ss))
            session_forget(ss);
        else if (session_age(ss) > so->max_age || session_too_old(ss))
            session_expire(ss);
    } 

    *pss = ss;

    return 0;
err:
    if(ss)
        session_free(ss);
    return ~0;
}

