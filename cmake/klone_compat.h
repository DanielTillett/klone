/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject
 * to the license stated in the LICENSE file which you have received as part
 * of this distribution.
 */

/* Names from before KLone was renamed Klin, for code written for KLone:
 * <klone/...> headers include this file. They will be removed in the next
 * release; use <klin/...>, klin_conf.h, klin_* and KLIN_* instead. */

#ifndef _KLONE_COMPAT_H_
#define _KLONE_COMPAT_H_

#include "klin_conf.h"

#define KLONE_VERSION           KLIN_VERSION
#define KLONE_VERSION_MAJOR     KLIN_VERSION_MAJOR
#define KLONE_VERSION_MINOR     KLIN_VERSION_MINOR
#define KLONE_VERSION_TEENY     KLIN_VERSION_TEENY

#define KLONE_FULL_BINDIR       KLIN_FULL_BINDIR
#define KLONE_FULL_SBINDIR      KLIN_FULL_SBINDIR
#define KLONE_FULL_SYSCONFDIR   KLIN_FULL_SYSCONFDIR
#define KLONE_FULL_INCLUDEDIR   KLIN_FULL_INCLUDEDIR
#define KLONE_FULL_LIBDIR       KLIN_FULL_LIBDIR
#define KLONE_FULL_LIBEXECDIR   KLIN_FULL_LIBEXECDIR
#define KLONE_FULL_LOCALSTATEDIR KLIN_FULL_LOCALSTATEDIR
#define KLONE_FULL_DATADIR      KLIN_FULL_DATADIR
#define KLONE_FULL_MANDIR       KLIN_FULL_MANDIR
#define KLONE_FULL_DOCDIR       KLIN_FULL_DOCDIR

#define KLONE_FREE              KLIN_FREE
#define KLONE_UNCONST           KLIN_UNCONST
#define klone_die               klin_die
#define klone_die_if            klin_die_if
#define klone_version           klin_version

#endif
