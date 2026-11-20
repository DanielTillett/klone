/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* The TLS key manager (doc/KEYMGR). The private key of an HTTPS server is
 * loaded once, at startup, and handed to a separate process, the key
 * manager, before any worker is forked; klind then wipes its own copy.
 * Workers only hold a proxy key: an OpenSSL 3 provider ("klin-keyproxy")
 * whose key management answers with the public key and whose signature
 * operation asks the key manager to sign the handshake digest. A worker
 * that is compromised can ask for signatures while it runs, but cannot
 * read or take the key.
 *
 * Each signature: the worker makes a socketpair, sends the request and
 * one end of the pair to the key manager over the control socket that all
 * processes inherited, and reads the answer on the other end. */

#include "klin_conf.h"

#ifdef SSL_OPENSSL
#ifndef OS_WIN

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <u/libu.h>
#include <klin/context.h>
#include <klin/keyproxy.h>
#include <klin/tlsprv.h>
#include <klin/sandbox.h>

#define KP_PROVIDER     "klin-keyproxy"
#define KP_PROPQ        "provider=klin-keyproxy"
#define KP_PARAM_PUBKEY "klin-pubkey"       /* DER SubjectPublicKeyInfo */
#define KP_PARAM_CHAN   "klin-channel"      /* control socket (int)     */

enum {
    KP_MAGIC = 0x6b6c6e6b,      /* "klnk"                               */
    KP_TBS_MAX = 128,           /* largest digest signed                */
    KP_SIG_MAX = 1024,          /* largest signature (RSA 8192)          */
    KP_TIMEOUT = 5000,          /* ms a worker waits for a signature     */
    KP_MAX_MANAGERS = 16
};

/* a request to the key manager, and its answer */
typedef struct
{
    uint32_t magic;
    uint32_t tbslen;
    char md[32];                /* digest name, "" if none               */
    char pad[16];               /* RSA padding mode, "" for the default  */
    char saltlen[16];           /* RSA-PSS salt length                   */
    char mgf1[32];              /* RSA-PSS MGF1 digest                   */
    unsigned char tbs[KP_TBS_MAX];
} kp_request_t;

typedef struct
{
    int32_t ok;
    uint32_t siglen;
    unsigned char sig[KP_SIG_MAX];
} kp_reply_t;

/* the key managers started (one per HTTPS server with a key) */
static pid_t kp_managers[KP_MAX_MANAGERS];
static size_t kp_nmanagers;

/* ------------------------------------------------------------------------
 * the key manager process
 * ---------------------------------------------------------------------- */

static void kp_sign(EVP_PKEY *key, const kp_request_t *rq, kp_reply_t *rp)
{
    EVP_PKEY_CTX *pc = NULL;
    OSSL_PARAM params[5], *p = params;
    size_t siglen = sizeof rp->sig;
    kp_request_t r = *rq;

    rp->ok = 0;
    rp->siglen = 0;

    /* the strings come from another process: terminate them */
    r.md[sizeof r.md - 1] = r.pad[sizeof r.pad - 1] = '\0';
    r.saltlen[sizeof r.saltlen - 1] = r.mgf1[sizeof r.mgf1 - 1] = '\0';
    if(r.magic != KP_MAGIC || r.tbslen == 0 || r.tbslen > KP_TBS_MAX)
        return;

    if(r.md[0])
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                r.md, 0);
    if(EVP_PKEY_is_a(key, "RSA"))
    {
        if(r.pad[0])
            *p++ = OSSL_PARAM_construct_utf8_string(
                    OSSL_SIGNATURE_PARAM_PAD_MODE, r.pad, 0);
        if(r.saltlen[0])
            *p++ = OSSL_PARAM_construct_utf8_string(
                    OSSL_SIGNATURE_PARAM_PSS_SALTLEN, r.saltlen, 0);
        if(r.mgf1[0])
            *p++ = OSSL_PARAM_construct_utf8_string(
                    OSSL_SIGNATURE_PARAM_MGF1_DIGEST, r.mgf1, 0);
    }
    *p = OSSL_PARAM_construct_end();

    if((pc = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)) != NULL &&
            EVP_PKEY_sign_init(pc) == 1 &&
            EVP_PKEY_CTX_set_params(pc, params) == 1 &&
            EVP_PKEY_sign(pc, rp->sig, &siglen, r.tbs, r.tbslen) == 1)
    {
        rp->ok = 1;
        rp->siglen = (uint32_t) siglen;
    }
    EVP_PKEY_CTX_free(pc);
}

/* drop root to the server's uid/gid (as klind will) and keep only the
   control socket */
static void kp_manager_setup(int chan)
{
    struct rlimit rl;
    int fd, uid = -1, gid = -1;

    /* the only descriptor the manager needs is the control socket */
    if(getrlimit(RLIMIT_NOFILE, &rl) != 0 || rl.rlim_cur > 65536)
        rl.rlim_cur = 1024;
    for(fd = 0; fd < (int) rl.rlim_cur; ++fd)
        if(fd != chan)
            (void) close(fd);
    if((fd = open("/dev/null", O_RDWR)) == 0)   /* 0, 1, 2 point nowhere */
    {
        (void) dup2(fd, 1);
        (void) dup2(fd, 2);
    }

    (void) signal(SIGPIPE, SIG_IGN);
    (void) signal(SIGINT, SIG_DFL);
    (void) signal(SIGTERM, SIG_DFL);
    (void) signal(SIGHUP, SIG_IGN);
    (void) signal(SIGCHLD, SIG_DFL);
    (void) signal(SIGALRM, SIG_IGN);

    if(ctx && ctx->config)
    {
        (void) u_config_get_subkey_value_i(ctx->config, "uid", -1, &uid);
        (void) u_config_get_subkey_value_i(ctx->config, "gid", -1, &gid);
    }

    /* as root with a uid and gid to run as: drop to them, or stop (a key
       manager must not go on as root when klind would not) */
    if((getuid() == 0 || geteuid() == 0) && uid > 0 && gid > 0 &&
            (setgroups(0, NULL) || setgid(gid) || setuid(uid)))
        _exit(1);
}

static void kp_manager_loop(EVP_PKEY *key, int chan, pid_t parent)
{
    struct pollfd pfd;
    struct msghdr mh;
    struct iovec iov;
    struct cmsghdr *cm;
    union { struct cmsghdr h; char buf[CMSG_SPACE(sizeof(int))]; } cbuf;
    kp_request_t rq;
    kp_reply_t rp;
    ssize_t n;
    int rfd;

    for(;;)
    {
        /* klind is gone: so is the key */
        if(getppid() != parent)
            _exit(0);

        pfd.fd = chan;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if(poll(&pfd, 1, 1000) <= 0)
            continue;

        memset(&mh, 0, sizeof mh);
        iov.iov_base = &rq;
        iov.iov_len = sizeof rq;
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cbuf.buf;
        mh.msg_controllen = sizeof cbuf.buf;

        if((n = recvmsg(chan, &mh, 0)) < 0)
            continue;

        rfd = -1;
        for(cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm))
            if(cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS)
                memcpy(&rfd, CMSG_DATA(cm), sizeof rfd);
        if(rfd < 0)
            continue;

        if(n == (ssize_t) sizeof rq && !(mh.msg_flags & (MSG_TRUNC|MSG_CTRUNC)))
            kp_sign(key, &rq, &rp);
        else
            memset(&rp, 0, sizeof rp);

        (void) send(rfd, &rp, sizeof rp, MSG_DONTWAIT);
        (void) close(rfd);
        OPENSSL_cleanse(&rq, sizeof rq);
    }
}

/* sign once before the sandbox closes in: OpenSSL fetches and sets up
   what signing needs on first use */
static void kp_warm_up(EVP_PKEY *key)
{
    kp_request_t rq;
    kp_reply_t rp;

    memset(&rq, 0, sizeof rq);
    rq.magic = KP_MAGIC;
    rq.tbslen = 32;
    strcpy(rq.md, "SHA256");
    kp_sign(key, &rq, &rp);
    OPENSSL_cleanse(&rp, sizeof rp);
}

/* start a key manager holding 'key'; *pchan: the control socket */
static int kp_manager_start(EVP_PKEY *key, int sandbox, int *pchan)
{
    int sv[2] = { -1, -1 };
    pid_t pid, parent = getpid();

    dbg_err_if(kp_nmanagers == KP_MAX_MANAGERS);
    dbg_err_sif(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));

    dbg_err_sif((pid = fork()) < 0);
    if(pid == 0)
    {   /* the key manager: never returns */
        kp_manager_setup(sv[1]);
        kp_warm_up(key);
        if(sandbox && sandbox_keymgr())
            _exit(1);
        kp_manager_loop(key, sv[1], parent);
        _exit(0);
    }

    close(sv[1]);
    /* the workers' end must not leak into exec'd CGIs */
    (void) fcntl(sv[0], F_SETFD, FD_CLOEXEC);
    kp_managers[kp_nmanagers++] = pid;
    *pchan = sv[0];

    return 0;
err:
    if(sv[0] >= 0)
        close(sv[0]);
    if(sv[1] >= 0)
        close(sv[1]);
    return ~0;
}

/* ------------------------------------------------------------------------
 * the worker side: ask the key manager for a signature
 * ---------------------------------------------------------------------- */

static int kp_request(int chan, const kp_request_t *rq, kp_reply_t *rp)
{
    struct msghdr mh;
    struct iovec iov;
    struct cmsghdr *cm;
    union { struct cmsghdr h; char buf[CMSG_SPACE(sizeof(int))]; } cbuf;
    struct pollfd pfd;
    int sv[2] = { -1, -1 }, rc;
    ssize_t n;

    nop_err_if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));

    memset(&mh, 0, sizeof mh);
    memset(&cbuf, 0, sizeof cbuf);
    iov.iov_base = (void *) rq;
    iov.iov_len = sizeof *rq;
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cbuf.buf;
    mh.msg_controllen = sizeof cbuf.buf;
    cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &sv[1], sizeof(int));

    do {
        n = sendmsg(chan, &mh, 0);
    } while(n < 0 && errno == EINTR);
    nop_err_if(n != (ssize_t) sizeof *rq);
    close(sv[1]);
    sv[1] = -1;

    pfd.fd = sv[0];
    pfd.events = POLLIN;
    do {
        pfd.revents = 0;
        rc = poll(&pfd, 1, KP_TIMEOUT);
    } while(rc < 0 && errno == EINTR);
    nop_err_if(rc <= 0);
    nop_err_if(recv(sv[0], rp, sizeof *rp, 0) != (ssize_t) sizeof *rp);
    close(sv[0]);

    return rp->ok ? 0 : ~0;
err:
    if(sv[0] >= 0)
        close(sv[0]);
    if(sv[1] >= 0)
        close(sv[1]);
    return ~0;
}

/* ------------------------------------------------------------------------
 * the provider: key management
 * ---------------------------------------------------------------------- */

typedef struct
{
    EVP_PKEY *pub;          /* the public key (default provider)        */
    int chan;               /* control socket of the key manager        */
} kp_key_t;

static void *kp_key_new(void *provctx)
{
    kp_key_t *k = OPENSSL_zalloc(sizeof *k);

    (void) provctx;
    if(k)
        k->chan = -1;
    return k;
}

static void kp_key_free(void *keydata)
{
    kp_key_t *k = keydata;

    if(k)
    {
        EVP_PKEY_free(k->pub);
        OPENSSL_free(k);
    }
}

static int kp_key_has(const void *keydata, int selection)
{
    const kp_key_t *k = keydata;

    /* the private key is the key manager's: signing works */
    (void) selection;
    return k != NULL && k->pub != NULL;
}

static int kp_key_match(const void *a, const void *b, int selection)
{
    const kp_key_t *ka = a, *kb = b;

    (void) selection;
    return ka && kb && ka->pub && kb->pub && EVP_PKEY_eq(ka->pub, kb->pub) == 1;
}

static int kp_key_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    kp_key_t *k = keydata;
    const OSSL_PARAM *p;
    const unsigned char *der;
    size_t len;

    (void) selection;
    if(k == NULL)
        return 0;
    if((p = OSSL_PARAM_locate_const(params, KP_PARAM_PUBKEY)) == NULL ||
            !OSSL_PARAM_get_octet_string_ptr(p, (const void **) &der, &len))
        return 0;
    EVP_PKEY_free(k->pub);
    if((k->pub = d2i_PUBKEY_ex(NULL, &der, (long) len, NULL,
                    "provider=default")) == NULL)
        return 0;
    if((p = OSSL_PARAM_locate_const(params, KP_PARAM_CHAN)) != NULL &&
            !OSSL_PARAM_get_int(p, &k->chan))
        return 0;
    return 1;
}

static const OSSL_PARAM *kp_key_import_types(int selection)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_octet_string(KP_PARAM_PUBKEY, NULL, 0),
        OSSL_PARAM_int(KP_PARAM_CHAN, NULL),
        OSSL_PARAM_END
    };

    (void) selection;
    return types;
}

/* export the public part (what comparing with the certificate's key, in
 * another key management, needs); never a private part */
static int kp_key_export(void *keydata, int selection, OSSL_CALLBACK *cb,
        void *cbarg)
{
    kp_key_t *k = keydata;
    OSSL_PARAM *params = NULL;
    int rc;

    if(k == NULL || k->pub == NULL ||
            (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 0;
    if(EVP_PKEY_todata(k->pub, EVP_PKEY_PUBLIC_KEY, &params) != 1)
        return 0;
    rc = cb(params, cbarg);
    OSSL_PARAM_free(params);
    return rc;
}

static const OSSL_PARAM *kp_rsa_export_types(int selection)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    (void) selection;
    return types;
}

static const OSSL_PARAM *kp_ec_export_types(int selection)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                NULL, 0),
        OSSL_PARAM_END
    };

    (void) selection;
    return types;
}

/* sizes, security bits, default digest, group...: the public key's */
static int kp_key_get_params(void *keydata, OSSL_PARAM params[])
{
    kp_key_t *k = keydata;

    return k && k->pub && EVP_PKEY_get_params(k->pub, params) == 1;
}

static const OSSL_PARAM *kp_key_gettable_params(void *provctx)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                NULL, 0),
        OSSL_PARAM_END
    };

    (void) provctx;
    return types;
}

static const char *kp_rsa_query(int op)
{
    return op == OSSL_OP_SIGNATURE ? "RSA" : NULL;
}

static const char *kp_ec_query(int op)
{
    return op == OSSL_OP_SIGNATURE ? "ECDSA" : NULL;
}

#define KP_KEYMGMT(name, exporttypes, query)                                  \
static const OSSL_DISPATCH name[] = {                                         \
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) kp_key_new },                   \
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) kp_key_free },                 \
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) kp_key_has },                   \
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void)) kp_key_match },               \
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) kp_key_import },             \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) kp_key_import_types }, \
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) kp_key_export },             \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) exporttypes },         \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) kp_key_get_params },     \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                      \
        (void (*)(void)) kp_key_gettable_params },                            \
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void)) query },       \
    { 0, NULL }                                                               \
};

KP_KEYMGMT(kp_rsa_keymgmt, kp_rsa_export_types, kp_rsa_query)
KP_KEYMGMT(kp_ec_keymgmt, kp_ec_export_types, kp_ec_query)

/* ------------------------------------------------------------------------
 * the provider: signature
 * ---------------------------------------------------------------------- */

typedef struct
{
    kp_key_t *key;
    EVP_MD_CTX *mdctx;      /* digest-sign: the digest being computed    */
    char md[32], pad[16], saltlen[16], mgf1[32];
} kp_sig_t;

static void *kp_sig_new(void *provctx, const char *propq)
{
    (void) provctx;
    (void) propq;
    return OPENSSL_zalloc(sizeof(kp_sig_t));
}

static void kp_sig_free(void *vctx)
{
    kp_sig_t *s = vctx;

    if(s)
    {
        EVP_MD_CTX_free(s->mdctx);
        OPENSSL_free(s);
    }
}

static void *kp_sig_dup(void *vctx)
{
    kp_sig_t *s = vctx, *d;

    if((d = OPENSSL_memdup(s, sizeof *s)) == NULL)
        return NULL;
    d->mdctx = NULL;
    if(s->mdctx && ((d->mdctx = EVP_MD_CTX_new()) == NULL ||
                !EVP_MD_CTX_copy_ex(d->mdctx, s->mdctx)))
    {
        kp_sig_free(d);
        return NULL;
    }
    return d;
}

/* a parameter as a string: utf8 as given, an integer converted (RSA pad
   modes and salt lengths have both forms) */
static int kp_param_str(const OSSL_PARAM *p, char *buf, size_t size,
        const char *const *names, int first, int count)
{
    const char *s;
    int v;

    if(p->data_type == OSSL_PARAM_UTF8_STRING)
    {
        if(!OSSL_PARAM_get_utf8_string_ptr(p, &s) || strlen(s) >= size)
            return 0;
        strcpy(buf, s);
        return 1;
    }
    if(!OSSL_PARAM_get_int(p, &v))
        return 0;
    if(names && v >= first && v < first + count && names[v - first] != NULL)
        return snprintf(buf, size, "%s", names[v - first]) < (int) size;
    return snprintf(buf, size, "%d", v) < (int) size;
}

static int kp_sig_set_params(void *vctx, const OSSL_PARAM params[])
{
    /* RSA_PKCS1_PADDING 1 .. RSA_PKCS1_PSS_PADDING 6; salt lengths -4..-1 */
    static const char *const pads[] = { "pkcs1", NULL, "none", NULL, "x931",
        "pss" };
    static const char *const salts[] = { "auto-digestmax", "max", "auto",
        "digest" };
    kp_sig_t *s = vctx;
    const OSSL_PARAM *p;

    if(params == NULL)
        return 1;
    if((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST)) &&
            !kp_param_str(p, s->md, sizeof s->md, NULL, 0, 0))
        return 0;
    if((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE)) &&
            !kp_param_str(p, s->pad, sizeof s->pad, pads, 1, 6))
        return 0;
    if((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN))
            && !kp_param_str(p, s->saltlen, sizeof s->saltlen, salts, -4, 4))
        return 0;
    if((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST))
            && !kp_param_str(p, s->mgf1, sizeof s->mgf1, NULL, 0, 0))
        return 0;
    return 1;
}

static const OSSL_PARAM *kp_sig_settable(void *vctx, void *provctx)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };

    (void) vctx;
    (void) provctx;
    return types;
}

static int kp_sig_get_params(void *vctx, OSSL_PARAM params[])
{
    kp_sig_t *s = vctx;
    OSSL_PARAM *p;

    if((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL &&
            !OSSL_PARAM_set_utf8_string(p, s->md))
        return 0;
    return 1;
}

static const OSSL_PARAM *kp_sig_gettable(void *vctx, void *provctx)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };

    (void) vctx;
    (void) provctx;
    return types;
}

static int kp_sig_init(void *vctx, void *provkey, const OSSL_PARAM params[])
{
    kp_sig_t *s = vctx;

    s->key = provkey;
    return s->key != NULL && kp_sig_set_params(s, params);
}

/* sign a digest through the key manager */
static int kp_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
        size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    kp_sig_t *s = vctx;
    kp_request_t rq;
    kp_reply_t rp;
    int size;

    if(s->key == NULL || s->key->pub == NULL ||
            (size = EVP_PKEY_get_size(s->key->pub)) <= 0)
        return 0;
    if(sig == NULL)
    {
        *siglen = (size_t) size;
        return 1;
    }
    if(tbslen == 0 || tbslen > KP_TBS_MAX || s->key->chan < 0)
        return 0;

    memset(&rq, 0, sizeof rq);
    rq.magic = KP_MAGIC;
    rq.tbslen = (uint32_t) tbslen;
    memcpy(rq.tbs, tbs, tbslen);
    memcpy(rq.md, s->md, sizeof rq.md);
    memcpy(rq.pad, s->pad, sizeof rq.pad);
    memcpy(rq.saltlen, s->saltlen, sizeof rq.saltlen);
    memcpy(rq.mgf1, s->mgf1, sizeof rq.mgf1);

    if(kp_request(s->key->chan, &rq, &rp) || rp.siglen > sigsize ||
            rp.siglen > sizeof rp.sig)
        return 0;
    memcpy(sig, rp.sig, rp.siglen);
    *siglen = rp.siglen;

    return 1;
}

static int kp_sig_digest_init(void *vctx, const char *mdname, void *provkey,
        const OSSL_PARAM params[])
{
    kp_sig_t *s = vctx;
    EVP_MD *md = NULL;
    int ok;

    if(!kp_sig_init(s, provkey, params))
        return 0;
    if(mdname && *mdname)
    {
        if(strlen(mdname) >= sizeof s->md)
            return 0;
        strcpy(s->md, mdname);
    }
    if(s->md[0] == '\0')
        return 0;   /* RSA and ECDSA sign a digest */

    EVP_MD_CTX_free(s->mdctx);
    if((s->mdctx = EVP_MD_CTX_new()) == NULL ||
            (md = EVP_MD_fetch(NULL, s->md, "provider=default")) == NULL)
        return 0;
    ok = EVP_DigestInit_ex2(s->mdctx, md, NULL);
    EVP_MD_free(md);
    return ok;
}

static int kp_sig_digest_update(void *vctx, const unsigned char *data,
        size_t len)
{
    kp_sig_t *s = vctx;

    return s->mdctx && EVP_DigestUpdate(s->mdctx, data, len);
}

static int kp_sig_digest_final(void *vctx, unsigned char *sig, size_t *siglen,
        size_t sigsize)
{
    kp_sig_t *s = vctx;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if(sig == NULL)
        return kp_sig_sign(s, NULL, siglen, 0, NULL, 0);
    if(s->mdctx == NULL || !EVP_DigestFinal_ex(s->mdctx, dgst, &dlen))
        return 0;
    return kp_sig_sign(s, sig, siglen, sigsize, dgst, dlen);
}

static const OSSL_DISPATCH kp_signature[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) kp_sig_new },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) kp_sig_free },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void)) kp_sig_dup },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void)) kp_sig_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) kp_sig_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        (void (*)(void)) kp_sig_digest_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        (void (*)(void)) kp_sig_digest_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        (void (*)(void)) kp_sig_digest_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void)) kp_sig_get_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        (void (*)(void)) kp_sig_gettable },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void)) kp_sig_set_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        (void (*)(void)) kp_sig_settable },
    { 0, NULL }
};

/* ------------------------------------------------------------------------
 * the provider itself
 * ---------------------------------------------------------------------- */

static const OSSL_ALGORITHM kp_keymgmts[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1", KP_PROPQ, kp_rsa_keymgmt,
        "proxy RSA key (the key manager signs)" },
    { "EC:id-ecPublicKey:1.2.840.10045.2.1", KP_PROPQ, kp_ec_keymgmt,
        "proxy EC key (the key manager signs)" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM kp_signatures[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1", KP_PROPQ, kp_signature, NULL },
    { "ECDSA", KP_PROPQ, kp_signature, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *kp_query(void *provctx, int op, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    switch(op)
    {
    case OSSL_OP_KEYMGMT:
        return kp_keymgmts;
    case OSSL_OP_SIGNATURE:
        return kp_signatures;
    }
    return NULL;
}

static const OSSL_DISPATCH kp_provider[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) kp_query },
    { 0, NULL }
};

static int kp_provider_init(const OSSL_CORE_HANDLE *handle,
        const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = kp_provider;
    *provctx = NULL;
    return 1;
}

static OSSL_PROVIDER *kp_prov_default, *kp_prov_proxy;

/* at exit, after the SSL contexts holding proxy keys are gone */
static void kp_provider_unload(void)
{
    if(kp_prov_proxy)
        (void) OSSL_PROVIDER_unload(kp_prov_proxy);
    if(kp_prov_default)
        (void) OSSL_PROVIDER_unload(kp_prov_default);
    kp_prov_proxy = kp_prov_default = NULL;
}

/* make the provider available (and keep the default one: loading any
 * provider explicitly turns off loading the default one implicitly) */
static int kp_provider_load(void)
{
    if(kp_prov_proxy)
        return 0;
    dbg_err_if(OSSL_PROVIDER_add_builtin(NULL, KP_PROVIDER,
                kp_provider_init) != 1);
    dbg_err_if((kp_prov_default = OSSL_PROVIDER_load(NULL, "default"))
            == NULL);
    dbg_err_if((kp_prov_proxy = OSSL_PROVIDER_load(NULL, KP_PROVIDER))
            == NULL);
    (void) atexit(kp_provider_unload);

    return 0;
err:
    kp_provider_unload();
    return ~0;
}

/* ------------------------------------------------------------------------
 * public functions
 * ---------------------------------------------------------------------- */

/**
 * \brief   Give the private key of an SSL context to a key manager
 *
 * Start a key manager process holding \p key and set, as the context's
 * private key, a proxy key that signs through it. The caller frees \p key
 * (its memory is wiped) before any worker is forked.
 *
 * \return \c 0 if successful, \c ~0 on error (e.g. a key that is neither
 *         RSA nor EC)
 */
int tls_keyproxy_use_key(SSL_CTX *c, EVP_PKEY *key, int sandbox)
{
    unsigned char *der = NULL;
    EVP_PKEY_CTX *pc = NULL;
    EVP_PKEY *proxy = NULL;
    OSSL_PARAM params[3];
    const char *type;
    int len, chan = -1;

    dbg_return_if (c == NULL || key == NULL, ~0);

    if(EVP_PKEY_is_a(key, "RSA"))
        type = "RSA";
    else if(EVP_PKEY_is_a(key, "EC"))
        type = "EC";
    else
        warn_err("key_manager: only RSA and EC keys are supported (set "
                "key_manager no for this key)");

    dbg_err_if(kp_provider_load());
    dbg_err_if((len = i2d_PUBKEY(key, &der)) <= 0);
    dbg_err_if(kp_manager_start(key, sandbox, &chan));

    params[0] = OSSL_PARAM_construct_octet_string(KP_PARAM_PUBKEY, der,
            (size_t) len);
    params[1] = OSSL_PARAM_construct_int(KP_PARAM_CHAN, &chan);
    params[2] = OSSL_PARAM_construct_end();

    dbg_err_if((pc = EVP_PKEY_CTX_new_from_name(NULL, type, KP_PROPQ)) == NULL);
    dbg_err_if(EVP_PKEY_fromdata_init(pc) != 1);
    dbg_err_if(EVP_PKEY_fromdata(pc, &proxy, EVP_PKEY_KEYPAIR, params) != 1);
    dbg_err_if(SSL_CTX_use_PrivateKey(c, proxy) != 1);

    EVP_PKEY_free(proxy);
    EVP_PKEY_CTX_free(pc);
    OPENSSL_free(der);

    return 0;
err:
    EVP_PKEY_free(proxy);
    EVP_PKEY_CTX_free(pc);
    OPENSSL_free(der);
    return ~0;
}

/**
 * \brief   Tell if \p pid was a key manager (its end is fatal: klind no
 *          longer has the key)
 */
int tls_keyproxy_is_manager(pid_t pid)
{
    size_t i;

    for(i = 0; i < kp_nmanagers; ++i)
        if(kp_managers[i] == pid)
            return 1;
    return 0;
}

/**
 * \brief   Stop the key managers (at shutdown)
 */
void tls_keyproxy_stop(void)
{
    size_t i;

    for(i = 0; i < kp_nmanagers; ++i)
        (void) kill(kp_managers[i], SIGTERM);
}

#else   /* OS_WIN */

#include <u/libu.h>
#include <klin/keyproxy.h>
#include <klin/tlsprv.h>

int tls_keyproxy_use_key(SSL_CTX *c, EVP_PKEY *key, int sandbox)
{
    u_unused_args(c, key, sandbox);
    warn("key_manager is not supported on this platform");
    return ~0;
}

int tls_keyproxy_is_manager(pid_t pid)
{
    u_unused_args(pid);
    return 0;
}

void tls_keyproxy_stop(void)
{
}

#endif  /* OS_WIN */
#endif  /* SSL_OPENSSL */
