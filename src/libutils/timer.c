/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of KLone, and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

#include "klone_conf.h"
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <klone/timer.h>
#include <klone/utils.h>
#include <u/libu.h>

#ifdef OS_WIN
#include <windows.h>
#endif

TAILQ_HEAD(talarm_list_s, talarm_s);
typedef struct talarm_list_s talarm_list_t;

typedef void (*timerm_cb_t)(int);

struct talarm_s
{
    TAILQ_ENTRY(talarm_s) np;   /* next & prev pointers         */
    timerm_t *timer;            /* timerm_t that owns the alarm */
    int64_t expire;             /* when to fire the alarm (ms)  */
    talarm_cb_t cb;             /* alarm callback               */
    void *arg;                  /* cb opaque argument           */
    pid_t owner;                /* process that set the alarm   */
};

struct timerm_s
{
    talarm_list_t alist;        /* alarm list                   */
    int64_t next;               /* next SIGALRM (ms), 0 if none */
    int cb_running;             /* set when timer callback is running */
#ifdef OS_WIN
    CRITICAL_SECTION cs;
    HANDLE hthread;             /* thread handle                */
    DWORD tid;                  /* thread id                    */
#endif
};

/* this must be a singleton */
static timerm_t *timer = NULL;

#ifdef OS_UNIX
/* The alarm list is guarded by a flag instead of blocking SIGALRM, which
 * costs two system calls each time: a SIGALRM that arrives while the list
 * is being changed is only recorded, and handled when the change is done. */
static volatile sig_atomic_t alarms_locked = 0;
static volatile sig_atomic_t alarm_pending = 0;

/* keep the compiler from moving list changes across the flag updates (the
 * handler runs on the same thread, so no CPU fence is needed) */
#if defined(__GNUC__) || defined(__clang__)
#define TIMERM_BARRIER() __asm__ __volatile__("" ::: "memory")
#else
#define TIMERM_BARRIER()
#endif
#endif

/* milliseconds of a clock that does not jump with the time of day: alarms
 * are timed in milliseconds so that one never fires early (with whole seconds
 * an alarm set at 0.999 for one second would run on any SIGALRM after 1.000) */
static int64_t timerm_now(void)
{
#if defined(OS_WIN)
    return (int64_t) GetTickCount64();
#else
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;

    if(clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
    return (int64_t) time(0) * 1000;
#endif
}

/* raise SIGALRM in 'ms' milliseconds unless it is already due sooner */
static int timerm_set_alarm(int64_t ms)
{
    int64_t secs = (ms + 999) / 1000;     /* alarm(2) counts whole seconds */
    int64_t n = timerm_now() + secs * 1000;

    if(secs > 0 && (timer->next == 0 || n < timer->next))
    {
        timer->next = n;
#ifdef OS_UNIX
        alarm((unsigned int) secs);
#endif
    } 

    return 0;
}

static int timerm_set_next(void)
{
    talarm_t *al = NULL;
    int64_t now = timerm_now();

    if((al = TAILQ_FIRST(&timer->alist)) != NULL)
        timerm_set_alarm(U_MAX(1, al->expire - now));

    return 0;
}

/* run the expired alarms */
static void timerm_run(void)
{
    talarm_t *al = NULL;
    pid_t pid = getpid();
    int64_t now = timerm_now();

    dbg_err_if(timer == NULL);

    timer->next = 0;

    for(;;)
    {
        /* get the topmost item and remove it from the list */
        al = TAILQ_FIRST(&timer->alist);
        nop_err_if(al == NULL);

        if(al->owner != pid)
        {
            /* this alert has been inherited from the parent, we cannot
             * timerm_del() it because the user may have a reference to it
             * somewhere so we just remove it from the list of timers */
            TAILQ_REMOVE(&timer->alist, al, np);
            continue;
        }

        if(al->expire > now)
            break;
        
        TAILQ_REMOVE(&timer->alist, al, np);

        /* use to serialize callbacks nd avoid handler recursive */
        timer->cb_running = 1;

        /* call the callback function */
        al->cb(al, al->arg);

        timer->cb_running = 0;
    }

    /* prepare for the next alarm */
    if(TAILQ_FIRST(&timer->alist))
        timerm_set_next();

err:
    return;
}

static void timerm_sigalrm(int sigalrm)
{
    u_unused_args(sigalrm);

#ifdef OS_UNIX
    if(alarms_locked)
    {
        /* the list is being changed: run the alarms when that is done */
        alarm_pending = 1;
        return;
    }
    alarms_locked = 1;
#endif

    timerm_run();

#ifdef OS_UNIX
    alarms_locked = 0;
#endif
}

static int timerm_block_alarms(void)
{
#ifdef OS_UNIX
    if(timer == NULL || timer->cb_running)
        return 0;
    alarms_locked = 1;
    TIMERM_BARRIER();
#endif

#ifdef OS_WIN
    EnterCriticalSection(&timer->cs);
#endif

    return 0;
}

static int timerm_unblock_alarms(void)
{
#ifdef OS_UNIX
    if(timer == NULL)
    {
        alarms_locked = 0;  /* e.g. on a timerm_add() error */
        return 0;
    }

    if(timer->cb_running)
        return 0;   /* the alarms run with the list locked */

    for(;;)
    {
        TIMERM_BARRIER();
        if(!alarm_pending)
        {
            alarms_locked = 0;

            /* a SIGALRM may have been deferred just before the unlock */
            if(!alarm_pending)
                break;
            alarms_locked = 1;
        }

        /* handle the deferred SIGALRM, still locked against a new one */
        alarm_pending = 0;
        timerm_run();
    }
#endif

#ifdef OS_WIN
    LeaveCriticalSection(&timer->cs);
#endif

    return 0;
}

static int timerm_free(timerm_t *t)
{
    talarm_t *a = NULL;

    dbg_return_if (t == NULL, ~0);
    
    if(t)
    {
        while((a = TAILQ_FIRST(&t->alist)) != NULL)
            dbg_if(timerm_del(a));

        U_FREE(t);
    }

    return 0;
}

#ifdef OS_WIN
static DWORD WINAPI thread_func(LPVOID param)
{
    for(;;Sleep(250))
    {
        if(timer->next == 0)
            continue;

        if((timer->next - timerm_now()) <= 0)
            timerm_sigalrm(0);  /* raise the alarm */
    }

    return 0;
}
#endif

static int timerm_create(timerm_t **pt)
{
    timerm_t *t = NULL;

    dbg_return_if (pt == NULL, ~0);

    t = u_zalloc(sizeof(timerm_t));
    dbg_err_if(t == NULL);

    TAILQ_INIT(&t->alist);

#ifdef OS_WIN
    InitializeCriticalSection(&t->cs);

    dbg_err_if((t->hthread = CreateThread(NULL, 0, thread_func, NULL, 0, 
        &t->tid)) == NULL); 
#endif

    *pt = t;

    return 0;
err:
    if(t)
        timerm_free(t);
    return ~0;
}

/* use this function if you need to re-set the alarm in the signal
 * handler (don't timerm_del() on the alarm) */
int timerm_reschedule(talarm_t *al, int secs, talarm_cb_t cb, void *arg)
{
    talarm_t *item = NULL;
    int64_t now = timerm_now();

    dbg_return_if (cb == NULL, ~0);
    dbg_return_if (al == NULL, ~0);

    al->cb = cb;
    al->arg = arg;
    al->expire = now + (int64_t) secs * 1000;

    dbg_err_if(timerm_block_alarms());

    /* insert al ordered by the expire field (smaller first) */
    TAILQ_FOREACH(item, &timer->alist, np)
        if(al->expire < item->expire)
            break; 
    
    if(item)
        TAILQ_INSERT_BEFORE(item, al, np);
    else
        TAILQ_INSERT_TAIL(&timer->alist, al, np);

    /* set the timer for the earliest alarm */
    timerm_set_next();
                                                              
    dbg_err_if(timerm_unblock_alarms());                      
                                                              
    return 0;                                                 
err:                                                          
    return ~0;                                                
}      

int timerm_add(int secs, talarm_cb_t cb, void *arg, talarm_t **pa)
{
    talarm_t *al = NULL;
    pid_t pid = getpid();

    dbg_return_if (cb == NULL, ~0);
    dbg_return_if (pa == NULL, ~0);

    if(timer == NULL)
    {
        dbg_err_if(timerm_create(&timer));
        #ifdef OS_UNIX
        dbg_err_if(u_signal(SIGALRM, timerm_sigalrm));
        #endif
    }

    al = (talarm_t*)u_zalloc(sizeof(talarm_t));
    dbg_err_if(al == NULL);

    al->timer = timer;
    al->owner = pid;

    dbg_err_if(timerm_reschedule(al, secs, cb, arg));

    *pa = al;

    return 0;
err:
    u_dbg("[%lu] timerm_add error", (unsigned long) getpid());
    if(timer)
    {
        (void) timerm_free(timer);
        timer = NULL;
    }
    U_FREE(al);

    dbg_err_if(timerm_unblock_alarms());

    return ~0;
}

static int timerm_alarm_pending(talarm_t *a)
{
    talarm_t *t;

    TAILQ_FOREACH(t, &timer->alist,np)
    {
        if(t == a)
            return 1;   /* found */
    }
    return 0;
}

int timerm_del(talarm_t *a)
{
    dbg_return_if(a == NULL, ~0);

    dbg_err_if(timerm_block_alarms());

    /* if not expired remove it from the list */
    if(timerm_alarm_pending(a))
        TAILQ_REMOVE(&timer->alist, a, np);

    /* set the timer for the earliest alarm */
    timerm_set_next();

    dbg_err_if(timerm_unblock_alarms());

    U_FREE(a);

    return 0;
err:
    dbg_err_if(timerm_unblock_alarms());
    return ~0;
}
