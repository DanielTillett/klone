/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klin_conf.h"
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <klin/http.h>
#include <klin/supplier.h>
#include <klin/io.h>
#include <klin/utils.h>
#include <klin/rsfilter.h>
#include <klin/timer.h>
#include <klin/vhost.h>
#include "http_s.h"

/* holds environment variables passed to the cgi */
typedef struct cgi_env_s
{
    char **env;
    int size, count;
} cgi_env_t;

/* limits of a cgi run (doc/CGI): seconds of wall-clock time and of CPU
 * time, MB of address space; 0 sets none */
enum { CGI_TIMEOUT = 60, CGI_MAX_CPU = 30, CGI_MAX_MEMORY = 512 };

typedef struct cgi_limits_s
{
    int timeout, max_cpu, max_memory;
} cgi_limits_t;

/* the running cgi, for the timeout alarm */
typedef struct cgi_run_s
{
    pid_t child;
    int timed_out;
} cgi_run_t;

/* request fields not passed to cgis unless "pass_headers" lists them:
 * credentials, which are for the server (doc/AUTH), not for every script */
static const char *cgi_private_fields[] = {
    "Authorization", "Proxy-Authorization", NULL
};

static int cgi_get_config(http_t *h, request_t *rq, u_config_t **pc)
{
    vhost_t *vhost;

    dbg_err_if(h == NULL);
    dbg_err_if(rq == NULL);

    dbg_err_if((vhost = http_get_vhost(h, rq)) == NULL);

    *pc = vhost->config;

    return 0;
err:
    return ~0;
}


/* the vhost's "cgi" block, or NULL */
static u_config_t *cgi_block(http_t *h, request_t *rq)
{
    u_config_t *base, *config;

    if(cgi_get_config(h, rq, &base) || u_config_get_subkey(base, "cgi", &config))
        return NULL;

    return config;
}

static int cgi_script(http_t *h, request_t *rq, const char *fqn)
{
    u_config_t *config, *sub, *base;
    const char *dir;
    int i, t;

    if(fqn == NULL)
        return 0;

    /* get cgi. config subtree */
    dbg_err_if(cgi_get_config(h, rq, &base));

    /* get cgi. config subtree */
    nop_err_if(u_config_get_subkey(base, "cgi", &config));

    /* for each script_di config item */
    for(i = 0; !u_config_get_subkey_nth(config, "script_alias", i, &sub); ++i)
    {
        if((dir = u_config_get_value(sub)) == NULL)
            continue; /* empty key */

        /* find the dir part of the "alias dir" value */
        for(t = strlen(dir) - 1; t > 0; --t)
            if(dir[t] == ' ' || dir[t] == '\t')
                break;

        if(t == 0)
            continue; /* malformed value */

        /* skip the blank */
        dir += ++t;

        /* the first part of fqn must be equal to p and the file must be +x */
        if(!strncmp(fqn, dir, strlen(dir)) && !access(fqn, X_OK))
            return 1; /* ok, fqn in in the dir_alias dir or in a subdir */
    }

err:
    return 0;
}

/* returns 1 if the file extension in one of those handled by cgi programs */
static int cgi_ext(http_t *h, request_t *rq, const char *fqn, 
        const char **phandler)
{
    u_config_t *config, *base;
    char buf[U_FILENAME_MAX];
    const char *handler, *ext = NULL;

    if(fqn == NULL)
        return 0;

    for(ext = NULL; *fqn; ++fqn) 
        if(*fqn == '.')
            ext = fqn;

    if(ext == NULL)
        return 0; /* file with no extension */

    ext++; /* skip '.' */

    /* get cgi. config subtree */
    dbg_err_if(cgi_get_config(h, rq, &base));

    /* get cgi. config subtree */
    nop_err_if(u_config_get_subkey(base, "cgi", &config));

    dbg_err_if(u_snprintf(buf, sizeof(buf), "%s.handler", ext));

    /* check for cgi extension handler */
    handler = u_config_get_subkey_value(config, buf);

    if(handler)
    {
        if(phandler)
            *phandler = handler;
        return 1;
    }

err:
    return 0;
}

static int cgi_setenv(cgi_env_t *env, const char *name, const char *value)
{
    enum { CHUNK = 32 };
    char *keyval = NULL, **nenv = NULL;
    int i, nl, vl;

    dbg_return_if(!env || !name || !value, ~0);

    if((nl = strlen(name)) == 0)
        return ~0;

    vl = strlen(value);

    /* alloc or realloc the array */
    if(env->size == 0 || env->size == env->count)
    {
        env->size += CHUNK;
        if(env->env == NULL)
            nenv = u_zalloc(env->size * sizeof(char*));
        else {
            nenv = u_realloc(env->env, env->size * sizeof(char*));
        }
        dbg_err_if(nenv == NULL);
        /* zero-out new elems */
        for(i = env->count; i < env->size; ++i)
            nenv[i] = NULL;
        env->env = nenv;
    }

    keyval = u_malloc(nl + vl + 2);
    dbg_err_if(keyval == NULL);

    sprintf(keyval, "%s=%s", name, value);

    env->env[env->count++] = keyval;

    return 0;
err:
    U_FREE(keyval);
    U_FREE(nenv);
    return ~0;
}

static int cgi_is_valid_uri(http_t *h, request_t *rq, const char *uri,
        size_t len, void **handle, time_t *mtime)
{
    struct stat st;
    char fqn[U_FILENAME_MAX];
    vhost_t *vhost;
    int fd, rc;

    dbg_return_if (uri == NULL, 0);
    dbg_return_if (mtime == NULL, 0);
    dbg_return_if (len + 1 > U_FILENAME_MAX, 0);

    memcpy(fqn, uri, len);
    fqn[len] = '\0';

    /* fqn must be already normalized */
    if(strstr(fqn, ".."))
        return 0;

    /* run_cgi no */
    if((vhost = http_get_vhost(h, rq)) == NULL || !vhost->run_cgi)
        return 0;

    /* the vhost's symlink policy (doc/FILES); the script needs no read
       permission (a binary may be execute-only) */
#ifdef O_PATH
    fd = http_open_file(h, rq, fqn, O_PATH);
#else
    fd = http_open_file(h, rq, fqn, O_RDONLY | O_NONBLOCK);
#endif
    if(fd < 0)
        return 0;
    rc = fstat(fd, &st);
    close(fd);

    if(rc == 0 && S_ISREG(st.st_mode))
    {
        /* if it's not a cgi given its extension of uri then exit */
        if(!cgi_ext(h, rq, fqn, NULL) && !cgi_script(h, rq, fqn))
            return 0;

        *mtime = st.st_mtime;
        *handle = NULL;
        return 1;
    } else
        return 0;
}

static int cgi_setenv_addr(cgi_env_t *env, const char *addr, 
        const char *label_addr, const char *label_port)
{
    char buf[128];
    
    if (u_addr_get_ip(addr, buf, sizeof buf) != NULL)
        dbg_err_if (cgi_setenv(env, label_addr, buf));

    if (u_addr_get_port(addr, buf, sizeof buf) != NULL)
        dbg_err_if (cgi_setenv(env, label_port, buf));

    return 0;
err:
    return ~0;
}

static int cgi_setenv_ctype(cgi_env_t *env, request_t *rq)
{
    const char *ct;

    if((ct = request_get_field_value(rq, "Content-type")) != NULL)
        dbg_err_if(cgi_setenv(env, "CONTENT_TYPE", ct));

    return 0;
err:
    return ~0;
}

static int cgi_setenv_clen(cgi_env_t *env, request_t *rq)
{
    char buf[32];
    ssize_t len;

    if((len = request_get_content_length(rq)) > 0)
    {
        dbg_err_if(u_snprintf(buf, sizeof(buf), "%ld", (long int) len));
        dbg_err_if(cgi_setenv(env, "CONTENT_LENGTH", buf));
    }

    return 0;
err:
    return ~0;
}

static int cgi_set_blocking(int fd)
{
    int flags;

    warn_err_sif((flags = fcntl(fd, F_GETFL)) < 0);

    nop_err_if(fcntl(fd, F_SETFL, flags & (~O_NONBLOCK)) < 0);

    return 0;
err:
    return ~0;
}

/* the variables of klind's own environment that "pass_env" lists */
static int cgi_pass_env(cgi_env_t *env, u_config_t *config)
{
    char list[1024], *name, *pp = NULL;
    const char *v, *value;

    if(config == NULL || (v = u_config_get_subkey_value(config, "pass_env"))
            == NULL)
        return 0;

    dbg_err_if(u_strlcpy(list, v, sizeof list));

    for(name = strtok_r(list, " \t", &pp); name; name = strtok_r(NULL, " \t", &pp))
        if((value = getenv(name)) != NULL)
            dbg_err_if(cgi_setenv(env, name, value));

    return 0;
err:
    return ~0;
}

/* whether a request field is passed to the cgi as HTTP_<name>: never
 * "Proxy" (HTTP_PROXY would be read as a proxy setting, "httpoxy") nor a
 * name with other than letters, digits and '-' (X-A and X_A would both be
 * HTTP_X_A); then those "pass_headers" lists, or "all", or by default all
 * but the credentials */
static int cgi_pass_field(u_config_t *config, const char *name)
{
    char list[1024], *tok, *pp = NULL;
    const char *v, **f;
    const unsigned char *p;

    if(!strcasecmp(name, "Proxy"))
        return 0;
    for(p = (const unsigned char *) name; *p; ++p)
        if(!isalnum(*p) && *p != '-')
            return 0;

    v = config ? u_config_get_subkey_value(config, "pass_headers") : NULL;

    if(v == NULL || !strcasecmp(v, "default"))
    {
        for(f = cgi_private_fields; *f; ++f)
            if(!strcasecmp(name, *f))
                return 0;
        return 1;
    }

    if(!strcasecmp(v, "all"))
        return 1;

    if(u_strlcpy(list, v, sizeof list))
        return 0;
    for(tok = strtok_r(list, " \t", &pp); tok; tok = strtok_r(NULL, " \t", &pp))
        if(!strcasecmp(tok, name))
            return 1;

    return 0;
}

static int cgi_makeenv(request_t *rq, response_t *rs, cgi_env_t *env)
{
    const char *addr, *cstr;
    header_t *h;
    field_t *field;
    u_config_t *config;
    char *p, buf[1024];

    u_unused_args(rs);

    config = cgi_block(request_get_http(rq), rq);
    dbg_err_if(cgi_pass_env(env, config));

    dbg_err_if(cgi_setenv(env, "SERVER_SOFTWARE", "klin/" KLIN_VERSION));
    dbg_err_if(cgi_setenv(env, "SERVER_PROTOCOL", "HTTP/1.0"));
    dbg_err_if(cgi_setenv(env, "GATEWAY_INTERFACE", "CGI/1.1"));
    dbg_err_if(cgi_setenv(env, "REDIRECT_STATUS", "200"));

    /* klin server address */
    if ((addr = request_get_addr(rq)) != NULL)
    {
        dbg_err_if(cgi_setenv_addr(env, addr, "SERVER_ADDR", "SERVER_PORT"));

        if ((u_addr_get_ip(addr, buf, sizeof(buf))) != NULL)
            dbg_err_if(cgi_setenv(env, "SERVER_NAME", buf));
    }

    /* client address */
    if ((addr = request_get_peer_addr(rq)) != NULL)
        dbg_err_if(cgi_setenv_addr(env, addr, "REMOTE_ADDR", "REMOTE_PORT"));

    /* method */
    dbg_err_if(cgi_setenv(env, "REQUEST_METHOD", request_get_method_name(rq)));

    /* the user of an authentication realm (doc/AUTH) */
    if((cstr = request_get_auth_user(rq)) != NULL)
        dbg_err_if(cgi_setenv(env, "REMOTE_USER", cstr));

    if(io_is_secure(request_io(rq)))
        dbg_err_if(cgi_setenv(env, "HTTPS", "on"));

    if((cstr = request_get_path_info(rq)) != NULL)
        dbg_err_if(cgi_setenv(env, "PATH_INFO", cstr));

    if((cstr = request_get_resolved_path_info(rq)) != NULL)
        dbg_err_if(cgi_setenv(env, "PATH_TRANSLATED", cstr));

    if((cstr = request_get_query_string(rq)) != NULL)
        dbg_err_if(cgi_setenv(env, "QUERY_STRING", cstr));

    /* content length */
    dbg_err_if(cgi_setenv_clen(env, rq));

    /* content type*/
    dbg_err_if(cgi_setenv_ctype(env, rq));

    if((cstr = request_get_filename(rq)) != NULL)
        dbg_err_if(cgi_setenv(env, "SCRIPT_NAME", cstr));

    if((cstr = request_get_uri(rq)) != NULL)
        dbg_err_if(cgi_setenv(env, "REQUEST_URI", cstr));

    if((cstr = request_get_resolved_filename(rq)) != NULL)
        dbg_err_if(cgi_setenv(env, "SCRIPT_FILENAME", cstr));

    if((cstr = getenv("SYSTEMROOT")) != NULL)
        dbg_err_if(cgi_setenv(env, "SYSTEMROOT", cstr));

    dbg_err_if((h = request_get_header(rq)) == NULL);

    /* export the client request headers prefixing them with HTTP_ */
    for(field = NULL; (field = header_next_field(h, NULL, field)) != NULL; )
    {
        if(!cgi_pass_field(config, field_get_name(field)))
            continue;

        dbg_err_if(u_snprintf(buf, sizeof(buf), "HTTP_%s", 
                    field_get_name(field)));

        /* convert the field name to uppercase and '-' to '_' */
        for(p = buf; *p && *p != ':'; ++p)
        {
            if(*p == '-')
                *p = '_';
            else
                *p = (char) toupper((unsigned char) *p);
        }

        if(field_get_value(field))
            dbg_err_if(cgi_setenv(env, buf, field_get_value(field)));
        else
            dbg_err_if(cgi_setenv(env, buf, ""));
    }

    return 0;
err:
    return ~0;
}

#define close_pipe(fd)                      \
    do {                                    \
        if(fd[0] != -1) close(fd[0]);       \
        if(fd[1] != -1) close(fd[1]);       \
    } while(0); 

/* set a resource limit of the cgi (soft and hard: it cannot raise it) */
static void cgi_rlimit(int resource, rlim_t value)
{
    struct rlimit rl;

    rl.rlim_cur = rl.rlim_max = value;
    (void) setrlimit(resource, &rl);
}

static void cgi_load_limits(http_t *h, request_t *rq, cgi_limits_t *lim)
{
    u_config_t *config = cgi_block(h, rq);

    lim->timeout = CGI_TIMEOUT;
    lim->max_cpu = CGI_MAX_CPU;
    lim->max_memory = CGI_MAX_MEMORY;

    if(config == NULL)
        return;

    (void) u_config_get_subkey_value_i(config, "timeout", CGI_TIMEOUT,
            &lim->timeout);
    (void) u_config_get_subkey_value_i(config, "max_cpu", CGI_MAX_CPU,
            &lim->max_cpu);
    (void) u_config_get_subkey_value_i(config, "max_memory", CGI_MAX_MEMORY,
            &lim->max_memory);
}

static int cgi_exec(request_t *rq, response_t *rs, const cgi_limits_t *lim,
        pid_t *pchild, int *pcgi_stdin, int *pcgi_stdout)
{
    enum { RD_END /* read end point */, WR_END /* write end point */};
    int cgi_stdin[2] = { -1, -1 };
    int cgi_stdout[2] = { -1, -1 };
    cgi_env_t cgi_env = { NULL, 0, 0 };
    http_t *h;
    const char *argv[] = { NULL, NULL, NULL };
    const char *cgi_file, *handler;
    char *p, *cgi_path = NULL;
    pid_t child = -1;   /* not forked yet: an error before is the parent's */
    int fd;

    dbg_err_if((h = request_get_http(rq)) == NULL);

    /* create a pair of parent<->child IPC channels */
    dbg_err_if(pipe(cgi_stdin) < 0);
    dbg_err_if(pipe(cgi_stdout) < 0);

    crit_err_if((child = fork()) < 0);

    if(child == 0)
    {   /* child */

        /* a process group of its own, which the timeout kills whole */
        (void) setpgid(0, 0);

        /* close one end of both channels */
        close(cgi_stdin[WR_END]);
        close(cgi_stdout[RD_END]);

        /* setup cgi stdout to point to the write end of the cgi_stdout pipe */
        close(STDOUT_FILENO);
        crit_err_if(dup2(cgi_stdout[WR_END], STDOUT_FILENO) < 0);
        close(cgi_stdout[WR_END]);

        /* setup cgi stdin to point to the read end of the cgi_stdin pipe */
        close(STDIN_FILENO);
        crit_err_if(dup2(cgi_stdin[RD_END], STDIN_FILENO) < 0);
        close(cgi_stdin[RD_END]);

        /* ignore cgi stderr */
        fd = open("/dev/null", O_WRONLY);
        dbg_err_if(fd < 0);
        crit_err_if(dup2(fd, STDERR_FILENO) < 0);
        close(fd);

        /* all standard descriptor must be blocking */
        cgi_set_blocking(STDOUT_FILENO);
        cgi_set_blocking(STDIN_FILENO);
        cgi_set_blocking(STDERR_FILENO);

        /* close any other open fd */
        for(fd = 3; fd < 255; ++fd) 
            close(fd);

        /* extract path name from cgi_file */
        dbg_err_if((cgi_file = request_get_resolved_filename(rq)) == NULL);

        cgi_path = u_strdup(cgi_file);
        dbg_err_if(cgi_path == NULL);

        /* cut out filename part */
        dbg_err_if((p = strrchr(cgi_path, '/')) == NULL);
        ++p; *p = 0;

        crit_err_sifm(chdir(cgi_path) < 0, "unable to chdir to %s", cgi_path);

        U_FREE(cgi_path);

        /* make the CGI environment vars array */
        crit_err_sif(cgi_makeenv(rq, rs, &cgi_env));

        /* the handler may be the path of the handler or "exec" that means that
         * the script must be run as is */
        if(!cgi_ext(h, rq, cgi_file, &handler) || !strcasecmp(handler, "exec"))
        {
            /* setup cgi argv (ISINDEX command line handling is not impl) */
            argv[0] = cgi_file;

        } else {
            /* run the handler of this file extension */
            argv[0] = handler;
            argv[1] = cgi_file;
        }

        /* its limits (doc/CGI), set last: the memory one would also bind
           this process (a sanitizer build maps far more than a script) */
        if(lim->max_cpu > 0)
        {
            /* SIGXCPU, then SIGKILL a second later */
            struct rlimit rl;

            rl.rlim_cur = (rlim_t) lim->max_cpu;
            rl.rlim_max = (rlim_t) lim->max_cpu + 1;
            (void) setrlimit(RLIMIT_CPU, &rl);
        }
        if(lim->max_memory > 0)
            cgi_rlimit(RLIMIT_AS, (rlim_t) lim->max_memory * 1024 * 1024);
        cgi_rlimit(RLIMIT_CORE, 0);

        /* run the cgi (never returns); execve() does not modify argv, its
         * prototype is just not const-qualified */
        crit_err_sif(execve(argv[0], KLIN_UNCONST(argv), cgi_env.env));

        /* never reached */

    } else if(child > 0) {
        /* parent */

        /* (both set it: either may run first) */
        (void) setpgid(child, child);

        /* close one end of both channels */
        close(cgi_stdin[RD_END]);
        close(cgi_stdout[WR_END]);

        /* return cgi read/write descriptors to the parent */
        *pcgi_stdin = cgi_stdin[WR_END];
        *pcgi_stdout = cgi_stdout[RD_END];
        *pchild = child;

        return 0;

    } else {
        warn_err("fork error");
    }

err:
    if(child == 0)
        _exit(1); /* children exit here on error */
    close_pipe(cgi_stdin);
    close_pipe(cgi_stdout);
    return ~0;
}

/* send the POSTed data (Content-Length bytes) to the cgi's stdin. The
 * script may not read it, so a broken pipe is not an error; one that reads
 * nothing while more than a pipe buffer is POSTed blocks this write (the
 * request's post_timeout then closes the connection) */
static int cgi_send_post(request_t *rq, int cgi_stdin)
{
    io_t *cgi_out = NULL;
    ssize_t clen;

    if(request_get_method(rq) != HM_POST ||
            (clen = request_get_content_length(rq)) <= 0)
        return 0;

    /* the descriptor is the caller's to close */
    crit_err_sif(io_fd_create(cgi_stdin, IO_FD_NO_FLAGS, &cgi_out));
    crit_if(io_copy(cgi_out, request_io(rq), clen) < 0);
    io_free(cgi_out);

    return 0;
err:
    return ~0;
}

/* read the cgi's header (its first lines) into the response: "Status" sets
 * the status, a "Location" alone means 302. The response filter prints the
 * merged header before the body */
static int cgi_merge_header(request_t *rq, response_t *rs, io_t *cgi_in)
{
    header_t *head;
    field_t *field;
    codec_t *filter = NULL;

    dbg_err_if((head = response_get_header(rs)) == NULL);

    dbg_err_if(response_filter_create(rq, rs, NULL, &filter));
    dbg_err_if(io_codec_add_tail(response_io(rs), filter));
    filter = NULL; /* io_t owns it */

    crit_err_if(header_load_ex(head, cgi_in, HLM_OVERRIDE));

    if((field = header_get_field(head, "Status")) != NULL &&
            field_get_value(field))
    {
        response_set_status(rs, atoi(field_get_value(field)));

        /* "Status" is for the server, not a header field to send */
        dbg_err_if(header_del_field(head, field));
        field_free(field);
    } else if(header_get_field(head, "Location"))
        response_set_status(rs, HTTP_STATUS_MOVED_TEMPORARILY);
    else
        response_set_status(rs, HTTP_STATUS_OK);

    return 0;
err:
    if(filter)
        codec_free(filter);
    return ~0;
}

/* copy the rest of the cgi's output to the client (if nothing is left the
 * filter prints the header and an empty body when the codecs are flushed) */
static void cgi_relay(io_t *cgi_in, io_t *out)
{
    char buf[4096];
    ssize_t n;

    while((n = io_read(cgi_in, buf, sizeof(buf))) > 0)
    {
        if(io_write(out, buf, n) < 0)
            break;
    }
}

/* kill the cgi and what it started */
static void cgi_kill(pid_t child)
{
    (void) kill(-child, SIGKILL);
    (void) kill(child, SIGKILL);
}

/* the cgi ran past its timeout: killed, its output ends */
static int cgi_cb_timeout(talarm_t *al, void *arg)
{
    cgi_run_t *run = (cgi_run_t *) arg;

    u_unused_args(al);

    run->timed_out = 1;
    cgi_kill(run->child);
    warn("cgi killed after its timeout (pid %d)", (int) run->child);

    return 0;
}

/* reap the cgi; after an error it is killed first, as nobody reads its
 * output any more */
static void cgi_wait(pid_t child, int failed)
{
    int status;

    if(failed)
        cgi_kill(child);

    if(waitpid(child, &status, 0) == child && !failed &&
            WIFEXITED(status) && WEXITSTATUS(status))
        warn("cgi exited with [%d]", WEXITSTATUS(status));
}

static int cgi_serve(request_t *rq, response_t *rs)
{
    const char *fqn, *filename;
    io_t *cgi_in = NULL;
    int cgi_stdin = -1, cgi_stdout = -1;
    pid_t child = -1;
    cgi_limits_t lim;
    cgi_run_t run = { -1, 0 };
    talarm_t *al = NULL;

    dbg_err_if (rq == NULL);
    dbg_err_if (rs == NULL);
    dbg_err_if (response_io(rs) == NULL);

    /* if something goes wrong return a "bad request" */
    response_set_status(rs, HTTP_STATUS_BAD_REQUEST);

    /* script file name */
    fqn = request_get_resolved_filename(rq);
    crit_err_if(fqn == NULL || (filename = strrchr(fqn, '/')) == NULL);
    filename++;

    /* run the CGI and return its stdin and stdout descriptor */
    cgi_load_limits(request_get_http(rq), rq, &lim);
    crit_err_if(cgi_exec(rq, rs, &lim, &child, &cgi_stdin, &cgi_stdout));

    /* killed when it runs too long (the alarm fires while its output or
       stdin is waited for) */
    run.child = child;
    if(lim.timeout > 0)
        dbg_err_if(timerm_add(lim.timeout, cgi_cb_timeout, &run, &al));

    /* by default disable caching */
    response_disable_caching(rs);

    /* the POSTed data, then EOF on the cgi's stdin */
    dbg_err_if(cgi_send_post(rq, cgi_stdin));
    close(cgi_stdin);
    cgi_stdin = -1;

    /* the cgi's output; the descriptor is closed below, not by io_free */
    crit_err_sif(io_fd_create(cgi_stdout, IO_FD_NO_FLAGS, &cgi_in));

    /* header of cgis whose name start with nph- must not be parsed */
    if(strncmp(filename, "nph-", 4))
    {
        if(cgi_merge_header(rq, rs, cgi_in))
        {
            /* killed before it sent its header: 504, with no body */
            dbg_err_if(!run.timed_out);
            response_set_status(rs, HTTP_STATUS_GATEWAY_TIMEOUT);
        }
    } else
        response_set_status(rs, HTTP_STATUS_OK);

    cgi_relay(cgi_in, response_io(rs));

    /* killed in the middle of its output: the client must not take it for
       the whole of it */
    if(run.timed_out)
        response_close_connection(rs);

    if(al)
        timerm_del(al);
    io_free(cgi_in);
    close(cgi_stdout);
    cgi_wait(child, 0);

    return 0;
err:
    if(al)
        timerm_del(al);
    if(cgi_in)
        io_free(cgi_in);
    if(cgi_stdin != -1)
        close(cgi_stdin);
    if(cgi_stdout != -1)
        close(cgi_stdout);
    if(child > 0)
        cgi_wait(child, 1);
    return ~0;
}

static int cgi_init(void)
{
    return 0;
}

static void cgi_term(void)
{
    return;
}

supplier_t sup_cgi = {
    "cgi supplier",
    cgi_init,
    cgi_term,
    cgi_is_valid_uri,
    cgi_serve
};

