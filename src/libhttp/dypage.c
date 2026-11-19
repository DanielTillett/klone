#include <klin/dypage.h>
#include <klin/session.h>
#include <klin/ses_prv.h>
#include <klin/rsfilter.h>

const char *dypage_get_param(dypage_args_t *args, const char *key)
{
    size_t i;

    for(i = 0; i < args->nparams; ++i)
        if(strcmp(key, args->params[i].key) == 0)
            return args->params[i].val;

    return "";
}

int dypage_serve(dypage_args_t *args)
{
    http_t *http = NULL;
    codec_t *filter = NULL;
    session_opt_t *so;
    request_t *rq;
    response_t *rs;
    session_t *ss;
    io_t *oio;

    dbg_return_if(args == NULL, ~0);

    dbg_return_if(args->rq == NULL, ~0);
    dbg_return_if(args->rs == NULL, ~0);
    dbg_return_if(args->fun == NULL, ~0);

    /* alias */
    rq = args->rq;
    rs = args->rs;

    /* output io object */
    oio = response_io(rs);

    /* get session options */
    dbg_err_if((http = request_get_http(rq)) == NULL);
    dbg_err_if((so = http_get_session_opt(http)) == NULL);

    /* parse URL encoded or POSTed data (POST must be read before) */
    dbg_err_if(request_parse_data(rq));

    /* create/get the session */
    dbg_err_if(session_create(so, rq, rs, &args->ss));

    /* alias */
    ss = args->ss;

    /* set some default values */
    dbg_err_if(response_set_content_type(rs, "text/html"));

    /* by default disable caching */
    response_disable_caching(rs);

    /* create a response filter (used to automatically print all header fields 
     * when the header buffer fills up) and attach it to the response io */
    dbg_err_if(response_filter_create(rq, rs, ss, &filter));
    io_codec_add_tail(oio, filter);

    /* run the page code */
    args->fun(args);

    /* flush the output buffer */
    io_flush(oio);

    /* if nothing has been printed by the script the filter prints the
     * header (and an empty body) when the server flushes the codecs */

    /* save and destroy the session */
    session_free(ss); args->ss = ss = NULL;

    return 0;
err:
    if(args->rs)
        io_flush(response_io(args->rs));
    if(args->ss)
    {
        session_free(args->ss);
        args->ss = NULL;
    }
    return ~0;
}

