/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* Session data as it is loaded (from a cookie, a file or memory): the
 * first input byte picks decryption (AES-256-CBC, a fixed key) and
 * decompression, the rest is the stored data. The HMAC of a client-side
 * session is checked before this, so this is what a client with the HMAC
 * key, or a corrupt session file, could make the server read. Cookie
 * header parsing is covered by fuzz_request. */

#include "fuzz.h"
#include <klin/io.h>
#include <klin/vars.h>
#include <klin/session.h>
#include <klin/ses_prv.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static session_opt_t so;
    session_t ss;
    char *buf;

    if(size < 1 || size > FUZZ_MAX)
        return 0;
    memset(&so, 0, sizeof so);
    so.compress = data[0] & 1;
#ifdef SSL_ON
    so.encrypt = (data[0] >> 1) & 1;
    so.cipher = KC_AES_256_CBC;
    memset(so.cipher_key, 0x4b, sizeof so.cipher_key);
    memset(so.session_key, 0x53, sizeof so.session_key);
#endif

    memset(&ss, 0, sizeof ss);
    ss.so = &so;
    if(vars_create(&ss.vars))
        abort();
    buf = fuzz_string(data + 1, size - 1);
    (void) session_prv_load_from_buf(&ss, buf, size - 1);
    (void) vars_free(ss.vars);
    free(buf);
    return 0;
}
