/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of KLone, and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#ifndef _KLONE_CGI_H_
#define _KLONE_CGI_H_

#include <klone/request.h>

#ifdef __cplusplus
extern "C" {
#endif 

int cgi_set_request(request_t *rq);

#ifdef __cplusplus
}
#endif 

#endif
