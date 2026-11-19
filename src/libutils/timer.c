/*
 * Copyright (c) 2005-2012 by KoanLogic s.r.l. <http://www.koanlogic.com>
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* Alarms without signals: an alarm runs when the process waits for a
 * descriptor in timerm_wait() (the io drivers call it while an alarm is set)
 * and is due, so callbacks run in ordinary code and may do anything. They
 * used to run in a SIGALRM handler, which limited them to async-signal-safe
 * work. The prefork watchdog, which must interrupt any code, has its own
 * signal in server.c. */

#include "klin_conf.h"
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <klin/timer.h>
#include <klin/utils.h>
#include <u/libu.h>

#ifdef OS_WIN
#include <windows.h>
#else
#include <poll.h>
#endif

/* pthread_atfork() is in libc here, no thread library is needed */
#if defined(OS_UNIX) && (defined(__GLIBC__) || defined(__APPLE__))
#include <pthread.h>
#define TIMERM_PID_CACHE
#endif

TAILQ_HEAD(talarm_list_s, talarm_s);
typedef struct talarm_list_s talarm_list_t;

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
    talarm_list_t alist;        /* alarm list, earliest first   */
};

/* this must be a singleton */
static timerm_t *timer = NULL;

#ifdef TIMERM_PID_CACHE
static pid_t timerm_pid = 0;    /* 0 until known, and again in a child */

static void timerm_forget_pid(void)
{
    timerm_pid = 0;
}
#endif

/* getpid() is a system call and an alarm is set for each request: remember
 * the pid, forgetting it after a fork */
static pid_t timerm_getpid(void)
{
#ifdef TIMERM_PID_CACHE
    static int registered = 0;

    if(timerm_pid == 0)
    {
        if(!registered)
        {
            if(pthread_atfork(NULL, NULL, timerm_forget_pid))
                return getpid();
            registered = 1;
        }
        timerm_pid = getpid();
    }

    return timerm_pid;
#else
    return getpid();
#endif
}

/* milliseconds of a clock that does not jump with the time of day */
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

/* the first time a (forked) process looks at the alarm list: drop the
 * alarms inherited from the parent (the user may still hold pointers to
 * them, so they are not freed) */
static void timerm_adopt(void)
{
    static pid_t list_pid = 0;
    pid_t pid = timerm_getpid();
    talarm_t *al, *next;

    if(timer == NULL || list_pid == pid)
        return;
    list_pid = pid;

    for(al = TAILQ_FIRST(&timer->alist); al != NULL; al = next)
    {
        next = TAILQ_NEXT(al, np);
        if(al->owner != pid)
            TAILQ_REMOVE(&timer->alist, al, np);
    }
}

/**
 * \brief   Run the alarms that are due
 *
 * Each callback runs once, after its alarm is taken off the list; it may
 * set alarms (timerm_reschedule() of its own included) and delete others.
 *
 * \return  milliseconds until the next alarm, or \c -1 if none is set
 */
int timerm_run(void)
{
    talarm_t *al;
    int64_t now;

    timerm_adopt();

    if(timer == NULL)
        return -1;

    for(now = timerm_now();; now = timerm_now())
    {
        if((al = TAILQ_FIRST(&timer->alist)) == NULL)
            return -1;

        if(al->expire > now)
            return (int) U_MIN(al->expire - now, INT32_MAX);

        TAILQ_REMOVE(&timer->alist, al, np);
        (void) al->cb(al, al->arg);
    }
}

/**
 * \brief   Tell whether an alarm is set in this process
 *
 * Cheap (no system call): the io drivers call it before each read and
 * write, and wait with timerm_wait() only when it is true.
 */
int timerm_armed(void)
{
    if(timer == NULL || TAILQ_EMPTY(&timer->alist))
        return 0;

    timerm_adopt();     /* the alarms may be the parent's */

    return !TAILQ_EMPTY(&timer->alist);
}

/**
 * \brief   Wait for a descriptor, running the alarms that come due
 *
 * Wait until \p *pfd is ready for \p events (::TIMERM_WAIT_READ and/or
 * ::TIMERM_WAIT_WRITE), running each alarm as it comes due. An alarm
 * callback may close the descriptor (an io_close() sets \p *pfd to \c -1):
 * the wait then fails.
 *
 * \param pfd     the descriptor, re-read after each alarm
 * \param events  what to wait for
 *
 * \return \c 0 when the descriptor is ready, non-zero if it was closed or
 *         on error
 */
int timerm_wait(int *pfd, int events)
{
    int ms, rc;

    dbg_return_if (pfd == NULL, ~0);

    for(;;)
    {
        ms = timerm_run();

        nop_err_if(*pfd < 0);   /* closed by an alarm */

#ifdef OS_WIN
        {
            fd_set rd, wr;
            struct timeval tv, *ptv = NULL;

            FD_ZERO(&rd); FD_ZERO(&wr);
            if(events & TIMERM_WAIT_READ)
                FD_SET((SOCKET) *pfd, &rd);
            if(events & TIMERM_WAIT_WRITE)
                FD_SET((SOCKET) *pfd, &wr);
            if(ms >= 0)
            {
                tv.tv_sec = ms / 1000;
                tv.tv_usec = (ms % 1000) * 1000;
                ptv = &tv;
            }
            rc = select(0, &rd, &wr, NULL, ptv);
            if(rc == SOCKET_ERROR)
                return 0;   /* not a socket: files are always ready */
        }
#else
        {
            struct pollfd p;

            p.fd = *pfd;
            p.events = ((events & TIMERM_WAIT_READ) ? POLLIN : 0) |
                ((events & TIMERM_WAIT_WRITE) ? POLLOUT : 0);
            p.revents = 0;

            rc = poll(&p, 1, ms);
            if(rc < 0 && errno == EINTR)
                continue;
            dbg_err_sif(rc < 0);
        }
#endif
        /* ready, or an error the read or write will report */
        if(rc > 0)
            return 0;
    }

err:
    return ~0;
}

static int timerm_create(timerm_t **pt)
{
    timerm_t *t = NULL;

    dbg_return_if (pt == NULL, ~0);

    t = u_zalloc(sizeof(timerm_t));
    dbg_err_if(t == NULL);

    TAILQ_INIT(&t->alist);

    *pt = t;

    return 0;
err:
    return ~0;
}

/* (re)insert 'al', which is off the list, to fire in 'secs' seconds */
int timerm_reschedule(talarm_t *al, int secs, talarm_cb_t cb, void *arg)
{
    talarm_t *item = NULL;

    dbg_return_if (cb == NULL, ~0);
    dbg_return_if (al == NULL, ~0);
    dbg_return_if (timer == NULL, ~0);

    timerm_adopt();

    al->cb = cb;
    al->arg = arg;
    al->expire = timerm_now() + (int64_t) secs * 1000;
    al->owner = timerm_getpid();

    /* insert al ordered by the expire field (smaller first) */
    TAILQ_FOREACH(item, &timer->alist, np)
        if(al->expire < item->expire)
            break;

    if(item)
        TAILQ_INSERT_BEFORE(item, al, np);
    else
        TAILQ_INSERT_TAIL(&timer->alist, al, np);

    return 0;
}

int timerm_add(int secs, talarm_cb_t cb, void *arg, talarm_t **pa)
{
    talarm_t *al = NULL;

    dbg_return_if (cb == NULL, ~0);
    dbg_return_if (pa == NULL, ~0);

    if(timer == NULL)
        dbg_err_if(timerm_create(&timer));

    al = (talarm_t*)u_zalloc(sizeof(talarm_t));
    dbg_err_if(al == NULL);

    al->timer = timer;

    dbg_err_if(timerm_reschedule(al, secs, cb, arg));

    *pa = al;

    return 0;
err:
    U_FREE(al);
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

/* remove the alarm if it has not fired, and free it */
int timerm_del(talarm_t *a)
{
    dbg_return_if(a == NULL, ~0);

    timerm_adopt();

    if(timer && timerm_alarm_pending(a))
        TAILQ_REMOVE(&timer->alist, a, np);

    U_FREE(a);

    return 0;
}
