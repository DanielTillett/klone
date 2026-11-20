/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* What klind's entry.c and an embedded site would provide: the fuzz
 * targets link klind's other objects but have their own main() (the
 * fuzzing engine's) and no site. */

#include "klin_conf.h"
#include <klin/context.h>

static context_t fuzz_context;
context_t *ctx = &fuzz_context;

void register_pages(void);
void unregister_pages(void);

void register_pages(void)
{
}

void unregister_pages(void)
{
}
