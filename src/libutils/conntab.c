/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* The table of connections being served (klin/conntab.h). It is created by
 * the first conntab_class(), in the parent before any worker forks, in
 * memory shared with them (anonymous MAP_SHARED); a process without it
 * (e.g. klin run as a CGI) has no caps. Slots are taken with an atomic
 * compare-and-swap of the owner's pid; counts are a scan of the slots, so
 * two workers racing for the last place may both be refused, never both
 * let in. */

#include "klin_conf.h"
#include <string.h>
#include <unistd.h>
#include <u/libu.h>
#include <klin/conntab.h>

#ifdef OS_UNIX
#include <sys/mman.h>
#endif

enum { PEER_MAX = 64 };

typedef struct {
    pid_t pid;              /* owner, 0 if free */
    int cls;                /* class of the connection */
    int stream;             /* !0 for a long-lived response */
    char peer[PEER_MAX];    /* client address */
} ct_slot_t;

typedef struct {
    int nclass;
    struct { int per_peer, streams; } caps[CONNTAB_CLASSES];
    ct_slot_t slot[CONNTAB_SLOTS];
} ct_table_t;

static ct_table_t *ct = NULL;
static ct_slot_t *mine = NULL;  /* this process's slot */

int conntab_class(int per_peer, int streams)
{
    int cls;

    if(ct == NULL)
    {
#ifdef OS_UNIX
        void *p = mmap(NULL, sizeof *ct, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

        dbg_err_if(p == MAP_FAILED);
        ct = p;
#else
        /* one process: nothing to share */
        dbg_err_if((ct = u_zalloc(sizeof *ct)) == NULL);
#endif
        memset(ct, 0, sizeof *ct);
    }

    dbg_err_if(ct->nclass == CONNTAB_CLASSES);
    cls = ct->nclass++;
    ct->caps[cls].per_peer = U_MAX(0, per_peer);
    ct->caps[cls].streams = U_MAX(0, streams);

    return cls;
err:
    return -1;
}

/* the connections of class 'cls' from 'peer' (any peer if NULL), or the
   streams of the class */
static int ct_count(int cls, const char *peer, int streams)
{
    int i, n = 0;
    ct_slot_t *s;

    for(i = 0; i < CONNTAB_SLOTS; ++i)
    {
        s = &ct->slot[i];
        if(__atomic_load_n(&s->pid, __ATOMIC_ACQUIRE) == 0 || s->cls != cls)
            continue;
        if(streams ? s->stream : (peer && !strncmp(s->peer, peer, PEER_MAX)))
            ++n;
    }

    return n;
}

int conntab_enter(int cls, const char *peer)
{
    pid_t none, me = getpid();
    int i;

    conntab_leave();
    if(ct == NULL || cls < 0 || cls >= ct->nclass || peer == NULL)
        return 0;

    for(i = 0; i < CONNTAB_SLOTS; ++i)
    {
        none = 0;
        if(ct->slot[i].pid == 0 && __atomic_compare_exchange_n(
                &ct->slot[i].pid, &none, me, 0, __ATOMIC_ACQ_REL,
                __ATOMIC_RELAXED))
            break;
    }
    if(i == CONNTAB_SLOTS)
        return 0;   /* more workers than slots: no cap for this one */

    mine = &ct->slot[i];
    mine->cls = cls;
    mine->stream = 0;
    (void) u_strlcpy(mine->peer, peer, PEER_MAX);
    __atomic_thread_fence(__ATOMIC_RELEASE);

    /* this connection counts too */
    if(ct->caps[cls].per_peer && ct_count(cls, peer, 0) > ct->caps[cls].per_peer)
    {
        conntab_leave();
        return ~0;
    }

    return 0;
}

int conntab_stream(void)
{
    int cls;

    if(mine == NULL)
        return 0;

    cls = mine->cls;
    mine->stream = 1;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if(ct->caps[cls].streams && ct_count(cls, NULL, 1) > ct->caps[cls].streams)
    {
        mine->stream = 0;
        return ~0;
    }

    return 0;
}

void conntab_leave(void)
{
    if(mine == NULL)
        return;

    mine->stream = 0;
    mine->peer[0] = '\0';
    __atomic_store_n(&mine->pid, 0, __ATOMIC_RELEASE);
    mine = NULL;
}

void conntab_reap(pid_t pid)
{
    int i;

    if(ct == NULL || pid <= 0)
        return;

    for(i = 0; i < CONNTAB_SLOTS; ++i)
        if(ct->slot[i].pid == pid)
        {
            ct->slot[i].stream = 0;
            __atomic_store_n(&ct->slot[i].pid, 0, __ATOMIC_RELEASE);
        }
}
