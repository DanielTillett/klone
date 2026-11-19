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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <u/libu.h>
#include <klin/os.h>
#include <klin/server.h>
#include <klin/emb.h>
#include <klin/context.h>
#include <klin/utils.h>
#include <klin/hook.h>
#include <klin/hookprv.h>
#include "main.h"
#include "server_s.h"

extern context_t* ctx;

/* embfs load config driver */
static int drv_io_open(const char *uri, void **parg);
static int drv_io_close(void *arg);
static char *drv_io_gets(void *arg, char *buf, size_t size);

static u_config_driver_t drv_embfs = { 
    drv_io_open, drv_io_close, drv_io_gets, NULL 
};

static int drv_io_open(const char *uri, void **parg)
{
    io_t *io = NULL;

    dbg_err_if(uri == NULL);
    dbg_err_if(strlen(uri) == 0);
    dbg_err_if(parg == NULL);

    warn_err_ifm(emb_open(uri, &io), 
            "unable to open embedded resource: %s", uri);

    *parg = io;

    return 0;
err: 
    if(io)
        io_free(io);
    return ~0;
}

static int drv_io_close(void *arg)
{
    io_t *io = (io_t*) arg;

    dbg_err_if(io == NULL);

    io_free(io);

    return 0;
err: 
    return ~0;
}

static char *drv_io_gets(void *arg, char *buf, size_t size)
{
    io_t *io = (io_t*)arg;

    dbg_err_if (arg == NULL);
    dbg_err_if (buf == NULL);
    
    nop_err_if(io_gets(io, buf, size) <= 0);

    return buf;
err: 
    return NULL;
}

int app_init(void)
{
    io_t *io = NULL;

    /* create a hook obj */
    dbg_err_if(hook_create(&ctx->hook));

    /* init embedded resources */
    emb_init();

    /* if -f is provided load the external config file */
    if(ctx->ext_config)
    {
        u_info("loading external config file: %s", ctx->ext_config);

        con_err_ifm(u_config_load_from_file(ctx->ext_config, &ctx->config),
                    "unable to load the configuration file: %s", 
                    ctx->ext_config);
    } else {
        /* if -f is not used load the default embfs config file (a site
           made before KLone was renamed Klin embeds /etc/kloned.conf) */
        embres_t *res;
        const char *conf = "/etc/klind.conf";

        if(emb_lookup(conf, &res) && !emb_lookup("/etc/kloned.conf", &res))
            conf = "/etc/kloned.conf";

        con_err_ifm(u_config_load_from_drv(conf, &drv_embfs, 0,
                    &ctx->config),
                    "embfs configuration file load error (%s)", conf);
    }

    if (ctx->cmd_config) {
        /* override with command-line arg config from standard input */
        con_err_ifm(u_config_load(ctx->config, 0, 1), 
                    "command-line configuration load error");
    }

    if(ctx->debug)
        u_config_print(ctx->config, 0);


    return 0;
err:
    if(io)
        io_free(io);
    app_term();
    return ~0;
}

int app_term(void)
{
    if(ctx && ctx->config)
    {
        u_config_free(ctx->config);
        ctx->config = NULL;
    }

    if(ctx && ctx->server)
    {
        server_free(ctx->server);
        ctx->server = NULL;
    }

    if(ctx && ctx->hook)
    {
        hook_free(ctx->hook);
        ctx->hook = NULL;
    }

    emb_term();

    return 0;
}

int app_run(void)
{
    /* create a server object and start its main loop */
    dbg_err_if(server_create(ctx->config, ctx->debug, &ctx->server));

    if(getenv("GATEWAY_INTERFACE"))
        dbg_err_if(server_cgi(ctx->server));
    else
        dbg_err_if(server_loop(ctx->server));


    return EXIT_SUCCESS;
err:
    return EXIT_FAILURE;
}

