/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* HTTP authentication input: the parameters of an Authorization header
 * (Digest), up to the first newline, then a users block (as in a
 * users_file) whose "digest" and "password" lines are looked up and
 * checked as a request would. */

#include "fuzz.h"
#include "src/libhttp/auth.c"

/* the stored password format (authhash.c) */
static const char AUTH_PBKDF2_PREFIX_FUZZ[] = "pbkdf2-sha256$";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *input, *nl, name[32], val[512], *users_text;
    const char *p, *v;
    u_config_t *users = NULL, *u;
    unsigned long iters;
    int i, alg;

    if(size > FUZZ_MAX)
        return 0;
    input = fuzz_string(data, size);
    if((nl = strchr(input, '\n')) != NULL)
        *nl = '\0';

    /* the Authorization parameters, as auth_digest() reads them */
    for(p = input; (p = auth_next_param(p, name, sizeof name, val, sizeof val)); )
    {
        if(strlen(name) >= sizeof name || strlen(val) >= sizeof val)
            abort();
        if(!strcasecmp(name, "algorithm"))
            (void) auth_alg_from_name(val);
    }
    (void) auth_in_list(input, "auth", 4);

    /* a users block, its users' HA1 for a realm and their stored password */
    if(nl && (users_text = strdup(nl + 1)) != NULL)
    {
        if(u_config_load_from_buf(users_text, strlen(users_text), &users) == 0)
        {
            (void) auth_check_users(users, "fuzz");
            for(i = 0; (u = u_config_get_child_n(users, "user", i)); ++i)
            {
                for(alg = AUTH_ALG_MD5; alg <= AUTH_ALG_SHA256; ++alg)
                    (void) auth_user_ha1(u, alg, "R");
                /* PBKDF2 is slow on purpose: only cheap iteration counts */
                v = u_config_get_subkey_value(u, "password");
                if(v && !strncmp(v, AUTH_PBKDF2_PREFIX_FUZZ,
                            sizeof AUTH_PBKDF2_PREFIX_FUZZ - 1) &&
                        (iters = strtoul(v + sizeof AUTH_PBKDF2_PREFIX_FUZZ - 1,
                                         NULL, 10)) > 0 && iters <= 16)
                    (void) auth_password_verify("secret", v);
            }
            u_config_free(users);
        }
        free(users_text);
    }

    free(input);
    return 0;
}
