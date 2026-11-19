/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <klin/version.h>
#include <u/libu.h>

/**
 *  \addtogroup ut 
 *  \{
 *      \par
 */

/**
 * \brief   Return Klin version string (x.y.z)
 * 
 * Return Klin version string in the format x.y.z.
 *
 * \return the version string
 */
const char *klin_version(void)
{
    return KLIN_VERSION;
}

/**
 *  \}
 */
