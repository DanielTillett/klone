#ifndef _KLIN_ACCESS_
#define _KLIN_ACCESS_
#include <u/libu.h>
#include <klin/header.h>
#include <klin/request.h>
#include <klin/response.h>

int access_log(http_t*, u_config_t *, request_t *, response_t *);

#endif
