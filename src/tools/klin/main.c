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
#ifdef HAVE_SYS_DIR
#include <sys/dir.h>
#endif
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD
#include <unistd.h>
#endif
#ifdef HAVE_GETOPT
#include <getopt.h>
#endif
#include <u/libu.h>
#include <klin/os.h>
#include <klin/request.h>
#include <klin/response.h>
#include <klin/translat.h>
#include <klin/utils.h>
#include <klin/run.h>
#include <klin/mime_map.h>
#include <klin/version.h>
#include <klin/auth.h>
#include "pm.h"

int facility = LOG_LOCAL0;

/* command list enums */
enum command_e { CMD_UNKNOWN, CMD_TRANS, CMD_IMPORT, CMD_PASSWD };

enum { MAX_REALMS = 16 };

/* runtime flags */
enum flags_e { FLAG_NONE, FLAG_VERBOSE };

typedef struct 
{
    char *file_in, *file_out;   /* [trans] input, output file       */
    char *depend_out;           /* [trans] depend output file       */
    char *uri;                  /* [trans] translated file uri      */
    int verbose;                /* >0 when verbose mode is on       */
    char **arg;                 /* argv                             */
    size_t narg;                /* argc                             */
    int cmd;                    /* command to run                   */
    char *base_uri;             /* site base uri                    */
    int encrypt;                /* >0 when encryption is enabled    */
    int compress;               /* >0 when compress is enabled      */
    pm_t *comp_patt;            /* compress file pattern            */
    pm_t *enc_patt;             /* encrypt file pattern             */
    pm_t *excl_patt;            /* exclude file pattern             */
    char *key_file;             /* encryption key file name         */
    io_t *ior;                  /* io register.c                    */
    io_t *ioc;                  /* io CMake page list               */
    int import_err;             /* >0 if a file or dir failed import */
    size_t ndir, nfile;         /* dir and file count               */
    size_t nexcl;               /* # of excluded files (-x)         */
    const char *realm[MAX_REALMS]; /* [passwd] Digest realms (-r)   */
    size_t nrealm;
    int md5;                    /* [passwd] MD5 Digest too (-m)     */
    unsigned long iterations;   /* [passwd] PBKDF2 iterations (-n)  */
} context_t;

context_t *ctx;


#define usage_if(expr)  if(expr) usage(); 

static void usage(void)
{
    static const char * us = 
"Usage: klin [-hvV] -c COMMAND OPTIONS ARGUMENTS\n"
"Version: %s - Copyright (c) 2005-2012 KoanLogic s.r.l.\n"
"Copyright (c) 2026 Daniel Tillett\n"
"All rights reserved.\n"
"\n"
"       -h            display this help\n"
"       -v            verbose mode\n"
"       -V            print Klin version and exit\n"
"       -c command    command to execute (see COMMAND LIST)\n"
"\n"
"\n"
"    COMMAND LIST:\n"
"       import        import a directory tree in the embedded filesystem\n"
"       translate     convert a file or a dynamic web page to a C file\n"
#ifdef SSL_ON
"       passwd        hash a password (read from stdin) for an auth user\n"
#endif
"\n"
"\n"
"    COMMANDS SYNTAX:\n"
"\n"
"       import OPTIONS dir\n"
"         -b URI      base URI\n"
"         -x pattern  exclude all files whose URI match the given pattern (*)\n"
#ifdef SSL_ON
"         -e pattern  encrypt all files whose URI match the given pattern (*)\n"
"         -k key_file encryption key filename\n"
"                     (KLIN_CIPHER_KEY environ var is used if not provided)\n"
#endif
#ifdef HAVE_LIBZ
"         -z          compress all compressable content (based on MIME types)\n"
"         -Z pattern  compress all files whose URI match the given pattern (*)\n"
#endif
"         dir         directory tree path\n"
"\n"
"         (*) may be used more then once\n"
"\n"
"       translate OPTIONS\n"
#ifdef SSL_ON
"         -E          encrypt file content\n"
#endif
"         -i file     input file\n"
#ifdef SSL_ON
"         -k key_file encryption key filename\n"
#endif
"         -o file     output file\n"
"         -u URI      URI of translated page\n"
#ifdef HAVE_LIBZ
"         -z          compress file content\n"
#endif
#ifdef SSL_ON
"\n"
"       passwd OPTIONS user\n"
"         -r realm    also write the Digest hashes for this realm (*)\n"
"         -m          also write MD5 Digest hashes (for old clients)\n"
"         -n count    PBKDF2 iterations (default 100000)\n"
"         user        user name; the password is the first line of stdin\n"
"                     (see doc/AUTH)\n"
#endif
"\n";

    fprintf(stderr, us, klin_version());

    exit(EXIT_FAILURE);
}

static void remove_trailing_slash(char *s)
{
    size_t len;
    
    dbg_ifb (s == NULL) return;
    
    len = strlen(s);
    if(len && s[len - 1] == '/')
        s[len - 1] = 0;
}

static int parse_opt(int argc, char **argv)
{
    int ret;
    char opts[512];

    if(argc == 1)
        usage();

    /* common switches */
    strcpy(opts, "hvVx:b:i:o:u:c:d:");

    /* encryption switches */
#ifdef SSL_ON
    strcat(opts, "k:e:Er:mn:");
#endif

    /* compression switches */
#ifdef HAVE_LIBZ
    strcat(opts, "zZ:");
#endif

    while((ret = getopt(argc, argv, opts)) != -1)
    {
        switch(ret)
        {
        case 'v': /* verbose on */
            ctx->verbose++;
            break;
        case 'V': /* print name/version info and exit */
            u_print_version_and_exit();
            break;

#ifdef SSL_ON
        case 'E': /* encryption on */
            ctx->encrypt = 1;
            break;
        case 'e': /* encrypt file pattern */
            dbg_err_if(pm_add(ctx->enc_patt, optarg));
            break;
        case 'k': /* encryption key filename */
            ctx->key_file = u_strdup(optarg);
            warn_err_if(ctx->key_file == NULL);
            break;
#endif

#ifdef HAVE_LIBZ
        case 'Z': /* compress file pattern */
            ctx->compress = 1;
            dbg_err_if(pm_add(ctx->comp_patt, optarg));
            break;
        case 'z': /* compress */
            ctx->compress = 1;
            break;
#endif
        case 'c': /* command */
            if(!strcasecmp(optarg, "import"))
                ctx->cmd = CMD_IMPORT;
            else if(!strcasecmp(optarg, "translate"))
                ctx->cmd = CMD_TRANS;
#ifdef SSL_ON
            else if(!strcasecmp(optarg, "passwd"))
                ctx->cmd = CMD_PASSWD;
#endif
            else
                con_err("unknown command: %s", optarg);
            break;
#ifdef SSL_ON
        case 'r': /* passwd: Digest realm */
            klin_die_if(ctx->nrealm == MAX_REALMS, "too many realms");
            ctx->realm[ctx->nrealm++] = optarg;
            break;
        case 'm': /* passwd: MD5 Digest too */
            ctx->md5 = 1;
            break;
        case 'n': /* passwd: PBKDF2 iterations */
            ctx->iterations = strtoul(optarg, NULL, 10);
            klin_die_if(ctx->iterations < 1 || ctx->iterations > 100000000,
                    "bad iteration count");
            break;
#endif
        case 'i': /* input file */
            ctx->file_in = u_strdup(optarg);
            warn_err_if(ctx->file_in == NULL);
            break;
        case 'x': /* exclude pattern */
            dbg_err_if(pm_add(ctx->excl_patt, optarg));
            break;
        case 'b': /* base_uri */
            ctx->base_uri = u_strdup(optarg);
            warn_err_if(ctx->base_uri == NULL);

            if(ctx->base_uri[0] != '/')
                klin_die("base URI must be absolute "
                          "(i.e. must start with a '/')");

            remove_trailing_slash(ctx->base_uri);

            break;
        case 'o': /* output file */
            ctx->file_out = u_strdup(optarg);
            warn_err_if(ctx->file_out == NULL);
            break;
        case 'd': /* kld depend output file */
            ctx->depend_out = u_strdup(optarg);
            warn_err_if(ctx->depend_out == NULL);
            break;
        case 'u': /* translated page uri */
            /* skip the first char to avoid MSYS path translation bug
             * (see klin-site.c) */
            ctx->uri = u_strdup(1+optarg);
            warn_err_if(ctx->uri == NULL);

            if(ctx->uri[0] != '/')
                klin_die("URI must be absolute (i.e. must start with a '/')");

            remove_trailing_slash(ctx->uri);

            break;
        default:
        case 'h': 
            usage();
        }
    }

    klin_die_if(ctx->cmd == 0, "missing command argument (-c)");
    ctx->narg = argc - optind;  /* # of args left */
    ctx->arg = argv + optind;   

    return 0;
err:
    return ~0;
}

static int set_key_from_file(trans_info_t *pti, const char *key_file)
{
    io_t *io = NULL;

    dbg_err_if (pti == NULL);
    dbg_err_if (key_file == NULL);
    
    dbg_err_if(u_file_open(key_file, O_RDONLY, &io));

    dbg_err_if(io_read(io, pti->key, CODEC_CIPHER_KEY_LEN) <= 0);
    
    io_free(io);

    return 0;
err:
    return ~0;
}

static int command_trans(void)
{
    trans_info_t ti;
    const mime_map_t *mm;
    struct stat st;
    char *key_env;
    int key_found = 0;

    if(ctx->narg != 0)
        usage();    /* no argument allowed */

    memset(&ti, 0, sizeof(trans_info_t));

    klin_die_if(!ctx->file_in, "input file name required (-i file)");
    klin_die_if(!ctx->file_out, "output file name required (-o file)");
    klin_die_if(!ctx->uri, "translated page URI required (-u uri)");

    if(ctx->verbose)
        u_con("translating %s to %s (uri: %s)", ctx->file_in, ctx->file_out, 
            ctx->uri);

    /* input file */
    u_strlcpy(ti.file_in, ctx->file_in, sizeof ti.file_in);

    /* output file */
    u_strlcpy(ti.file_out, ctx->file_out, sizeof ti.file_out);

    /* kld depend file */
    if(ctx->depend_out)
        u_strlcpy(ti.depend_out, ctx->depend_out, sizeof ti.depend_out);

    /* uri */
    u_strlcpy(ti.uri, ctx->uri, sizeof ti.uri);

    /* zero out the key (some byte could not be overwritten with small keys) */
    memset(ti.key, 0, CODEC_CIPHER_KEY_BUFSZ);

    /* sanity checks */
    con_err_ifm(ctx->key_file && !ctx->encrypt, "-k used but -E is missing");

    /* encryption key */
    key_env = getenv("KLIN_CIPHER_KEY");
    if(key_env == NULL || !strlen(key_env))
        key_env = getenv("KLONE_CIPHER_KEY");  /* name before the rename */
    if(key_env && strlen(key_env))
    {
        con_err_ifm(strlen(key_env) != CODEC_CIPHER_KEY_LEN,
                "wrong key length; the encryption key must be %d bytes long",
                CODEC_CIPHER_KEY_LEN);

        key_found = 1;
		memcpy(ti.key, key_env, strlen(key_env));
    }

    /* if -k has been used the overwrite KLIN_CIPHER_KEY env var (if present)*/
    if(ctx->key_file)
    {
        key_found = 1;
        con_err_ifm(set_key_from_file(&ti, ctx->key_file), 
            "error reading key file [%s]", ctx->key_file);
    }

    if(ctx->encrypt)
    {
        if(!key_found)
            con_err("encryption key required (use -k or KLIN_CIPHER_KEY "
                    "environ variable)");
        ti.encrypt = 1;
    }

    /* set MIME type */
    if((mm = u_get_mime_map(ctx->file_in)) != NULL)
        u_strlcpy(ti.mime_type, mm->mime_type, sizeof ti.mime_type);
    else
        u_strlcpy(ti.mime_type, "application/octet-stream", 
                sizeof ti.mime_type);

    /* compress if requested and the file is compressable (by MIME type) */
    if(ctx->compress)
        ti.comp = 1;

    /* be sure that the input file exists */
    klin_die_if(stat(ctx->file_in, &st), "input file not found");

    ti.file_size = st.st_size;
    ti.mtime = st.st_mtime; 

    /* translate it */
    dbg_err_if(translate(&ti));

    return 0;
err:
    /* delete output file on error */
    u_remove(ti.file_out);
    u_con(" ");
    return ~0;
}

/* !0 if s can be wrapped in a bracket argument closed by 'close': it must
 * not contain 'close', nor end with its prefix (e.g. "x]" + "]]" -> "x]]]") */
static int cmake_bracket_safe(const char *s, const char *close)
{
    size_t slen = strlen(s), plen = strlen(close) - 1;

    if(strstr(s, close))
        return 0;

    return !(slen >= plen && strncmp(s + slen - plen, close, plen) == 0);
}

/* return the '=' run of a CMake bracket argument ([=[...]=]) that is safe
 * for all three strings, so any file name can be quoted verbatim */
static const char *cmake_bracket_eq(const char *a, const char *b,
        const char *c)
{
    enum { MAX_EQ = 16 };
    static char eq[MAX_EQ + 1];
    char close[MAX_EQ + 3];
    size_t n;

    for(n = 0; n <= MAX_EQ; ++n)
    {
        memset(eq, '=', n);
        eq[n] = '\0';
        (void) u_snprintf(close, sizeof close, "]%s]", eq);
        if(cmake_bracket_safe(a, close) && cmake_bracket_safe(b, close) &&
                cmake_bracket_safe(c, close))
            return eq;
    }

    return NULL;
}

static int cb_file(struct dirent *de, const char *path , void *arg)
{
    const mime_map_t *mm;
    char uri_md5[MD5_DIGEST_BUFSZ];
    char uri[URI_BUFSZ], *base_uri = (char*)arg;
    char fullpath[U_FILENAME_MAX];
    const char *ext, *key, *eq;
    int is_a_script, enc = 0, zip = 0;

    dbg_err_if (de == NULL);
    dbg_err_if (path == NULL);
    dbg_err_if (arg == NULL);

    dbg_err_if(u_snprintf(fullpath, U_FILENAME_MAX, "%s/%s", path, de->d_name));

    /* base uri */
    dbg_err_if(u_snprintf(uri, URI_BUFSZ, "%s/%s", base_uri, de->d_name));
    dbg_err_if(u_md5(uri, strlen(uri), uri_md5));

    /* if the URI match the given exclude pattern then skip it */
    if(!pm_is_empty(ctx->excl_patt) && pm_match(ctx->excl_patt, uri))
    {
        if(ctx->verbose)
            u_con("%s skipped", uri);

        ctx->nexcl++;

        return 0; /* skip it */
    } 

    is_a_script = translate_is_a_script(de->d_name);

    ctx->nfile++;

    /* if the URI match the given encrypt pattern then encrypt it */
    if(!pm_is_empty(ctx->enc_patt) && pm_match(ctx->enc_patt, uri))
        enc = 1;

    if(ctx->compress) /* -z or -Z have been used */
    {
        /* if the URI match the given compress pattern then compress it */
        if(!pm_is_empty(ctx->comp_patt))
        {   /* compression enabled basing on file URI pattern */
            if(pm_match(ctx->comp_patt, uri))
                zip = 1;
        } else {
            /* compression enabled basing on URI MIME types */
            if((mm = u_get_mime_map(uri)) != NULL)
                zip = mm->comp;
        }
    }

    /* print out some info */
    if(ctx->verbose == 1)
        u_con("%s (encrypted: %s, compressed: %s)", 
            uri, enc ? "yes" : "no", zip ? "yes" : "no");
    else if(ctx->verbose > 1)
        u_con("%s -> %s (encrypted: %s, compressed: %s)",
            fullpath, uri, enc ? "yes" : "no", zip ? "yes" : "no");

    ext = u_match_ext(fullpath, "klx") ? "cc" : "c";

    dbg_err_if(io_printf(ctx->ior, "KLIN_REGISTER(action,%s);\n", uri_md5) <0);

    /* page entry for cmake/site/CMakeLists.txt:
     * md5 ext file uri script zip enc key */
    key = enc && ctx->key_file ? ctx->key_file : "";
    eq = cmake_bracket_eq(fullpath, uri, key);
    dbg_err_if(eq == NULL);
    dbg_err_if(io_printf(ctx->ioc,
            "klin_site_page(%s %s [%s[%s]%s] [%s[%s]%s] %d %d %d [%s[%s]%s])\n",
            uri_md5, ext, eq, fullpath, eq, eq, uri, eq, is_a_script ? 1 : 0,
            zip, enc, eq, key, eq) < 0);

    return 0;
err:
    /* u_foreach_dir_item() stops on error but does not report it */
    ctx->import_err = 1;
    return ~0;
}

static int cb_dir(struct dirent *de, const char *path , void *arg)
{
    char dir[U_FILENAME_MAX], base_uri[URI_BUFSZ], *cur_uri = (char*)arg;

    dbg_err_if (de == NULL);
    dbg_err_if (path == NULL);
    dbg_err_if (arg == NULL);
    
    ctx->ndir++;

    dbg_err_if(u_snprintf(dir, U_FILENAME_MAX, "%s/%s", path, de->d_name));

    dbg_err_if(u_snprintf(base_uri, URI_BUFSZ, "%s/%s", cur_uri, de->d_name));

    dbg_err_if(u_foreach_dir_item(dir, S_IFREG, cb_file, (void*)base_uri));

    dbg_err_if(u_foreach_dir_item(dir, S_IFDIR, cb_dir, (void*)base_uri));

    return ctx->import_err ? ~0 : 0;
err:
    ctx->import_err = 1;
    return ~0;
}

static int print_register_header(io_t *out)
{
    dbg_err_if (out == NULL);
 
    dbg_err_if(io_printf(out, "#include <klin_conf.h>\n") < 0);
    dbg_err_if(io_printf(out, "#include <klin/hook.h>\n") < 0);
    dbg_err_if(io_printf(out, "static void do_register(int);\n") < 0);
    dbg_err_if(io_printf(out, "void unregister_pages(void);\n") < 0);
    dbg_err_if(io_printf(out, "void register_pages(void);\n") < 0);

    dbg_err_if(io_printf(out, 
        "void unregister_pages(void) { \n"
        "do_register(0); }\n"
        ) < 0);
    dbg_err_if(io_printf(out, 
        "void register_pages(void) { \n"
        "do_register(1);\n"
        "#ifdef ENABLE_HOOKS\n"
        "    hooks_setup(); \n"
        "#endif \n"
        "}\n") < 0);
    dbg_err_if(io_printf(out, 
        "static void do_register(int action) {\n") < 0);
    dbg_err_if(io_printf(out,
        "#define KLIN_REGISTER(a, md5)     \\\n"
        "    do {                           \\\n"
        "    void module_init_##md5(void);  \\\n"
        "    void module_term_##md5(void);  \\\n"
        "    if(a) module_init_##md5();     \\\n"
        "    else module_term_##md5();      \\\n"
        "    } while(0)                     \n") < 0);

    return 0;
err:
    return ~0;
}

static int print_register_footer(io_t *out)
{
    dbg_err_if (out == NULL);

    dbg_err_if(io_printf(out, "#undef KLIN_REGISTER\n") < 0);
    dbg_err_if(io_printf(out, "}\n") < 0);

    return 0;
err:
    return ~0;
}

static int trans_site(char *root_dir, char *base_uri)
{
    dbg_err_if (root_dir == NULL);
    dbg_err_if (base_uri == NULL);
    
    dbg_err_if(u_file_open("register.c", O_CREAT | O_TRUNC | O_WRONLY,
                &ctx->ior));

    /* page list read by cmake/site/CMakeLists.txt */
    dbg_err_if(u_file_open("autogen.cmake", O_CREAT | O_TRUNC | O_WRONLY,
                &ctx->ioc));

    dbg_err_if(print_register_header(ctx->ior));

    /* for each file call cb_file */
    dbg_err_if(u_foreach_dir_item(root_dir, S_IFREG, cb_file, base_uri));
    /* for each directory call cb_dir */
    dbg_err_if(u_foreach_dir_item(root_dir, S_IFDIR, cb_dir, base_uri));
    con_err_ifm(ctx->import_err, "import failed");

    dbg_err_if(print_register_footer(ctx->ior));

    /* write errors (e.g. a full disk) may only show up when flushing */
    con_err_ifm(io_flush(ctx->ioc) || io_flush(ctx->ior),
        "error writing import files");

    io_free(ctx->ioc);
    io_free(ctx->ior);

    return 0;
err:
    if(ctx->ioc)
        io_free(ctx->ioc);
    if(ctx->ior)
        io_free(ctx->ior);
    return ~0;
}

static int command_import(void)
{
    static char empty[] = "";
    char *root_dir, *base_uri;

    if(ctx->narg != 1)
        usage();    /* just on directory expected */

    root_dir = ctx->arg[0];
    dbg_err_if(root_dir == NULL);

    base_uri = ctx->base_uri ? ctx->base_uri : empty;

    dbg_err_if(trans_site(root_dir, base_uri));

    u_con("%lu dirs and %lu files imported, %lu files skipped", 
            (unsigned long) ctx->ndir, (unsigned long) ctx->nfile, 
            (unsigned long) ctx->nexcl);

    return 0;
err:
    u_con("import error");
    return ~0;
}

#ifdef SSL_ON
/* print a "user" block for an auth configuration (doc/AUTH): the PBKDF2
 * hash Basic checks, and the Digest HA1 of each realm asked for */
static int command_passwd(void)
{
    char pw[1024], hash[AUTH_PASSWORD_SZ], ha1[AUTH_HEX_SZ], *nl;
    const char *user;
    size_t i, len;
    int alg;

    usage_if(ctx->narg != 1);
    user = ctx->arg[0];
    klin_die_if(strpbrk(user, ":\"\\ \t") != NULL,
            "a user name cannot contain ':', quotes, backslashes or blanks");

    klin_die_if(fgets(pw, sizeof pw, stdin) == NULL, "no password on stdin");
    if((nl = strpbrk(pw, "\r\n")) != NULL)
        *nl = '\0';
    len = strlen(pw);
    klin_die_if(len == 0, "empty password");

    klin_die_if(auth_password_hash(pw, ctx->iterations ? (unsigned int)
                ctx->iterations : AUTH_PBKDF2_ITERATIONS, hash, sizeof hash),
            "cannot hash the password");

    printf("user\n{\n    name %s\n    roles\n    password %s\n", user, hash);

    for(i = 0; i < ctx->nrealm; ++i)
    {
        for(alg = AUTH_ALG_SHA256; alg >= AUTH_ALG_MD5; --alg)
        {
            if(alg == AUTH_ALG_MD5 && !ctx->md5)
                continue;
            klin_die_if(auth_digest_ha1(alg, user, ctx->realm[i], pw, ha1),
                    "cannot hash the password");
            printf("    digest %s %s %s\n", auth_alg_name(alg), ha1,
                    ctx->realm[i]);
        }
    }

    printf("}\n");
    memset(pw, 0, sizeof pw);

    return 0;
}
#endif

static int dispatch_command(void)
{
    switch(ctx->cmd)
    {
    case CMD_TRANS:
        dbg_err_if(command_trans());
        break;
    case CMD_IMPORT:
        dbg_err_if(command_import());
        break;
#ifdef SSL_ON
    case CMD_PASSWD:
        dbg_err_if(command_passwd());
        break;
#endif
    default:
        con_err("unknown command");
    }

    return 0;
err:
    return ~0;
}

int main(int argc, char **argv)
{
    context_t context;
    int result = EXIT_FAILURE;

    ctx = &context;

    /* zero-out the context */
    memset(ctx, 0, sizeof(context_t));

    /* init pattern matching objects */
    dbg_err_if(pm_create(&ctx->comp_patt));
    dbg_err_if(pm_create(&ctx->enc_patt));
    dbg_err_if(pm_create(&ctx->excl_patt));

    /* parse command line switches and set ctx->cmd and params */
    dbg_err_if(parse_opt(argc, argv));

    /* run the command */
    dbg_err_if(dispatch_command());

    result = EXIT_SUCCESS;
err:
    if (ctx->comp_patt) pm_free(ctx->comp_patt);
    if (ctx->enc_patt) pm_free(ctx->enc_patt);
    if (ctx->excl_patt) pm_free(ctx->excl_patt);
    U_FREE(ctx->file_in);
    U_FREE(ctx->file_out);
    U_FREE(ctx->depend_out);
    U_FREE(ctx->uri);
    U_FREE(ctx->base_uri);
    U_FREE(ctx->key_file);
    return result;
}
