/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* Process sandboxes (doc/SANDBOX). On Linux a seccomp-bpf filter: the
 * system calls a worker (or the TLS key manager) needs are allowed, those
 * only an attacker needs (ptrace, mount, setuid, module loading, bpf,
 * namespaces...) kill the process, and any other call fails with EPERM.
 * On OpenBSD, pledge(2). Elsewhere nothing is done. */

#include "klin_conf.h"
#include <errno.h>
#include <string.h>
#include <u/libu.h>
#include <klin/sandbox.h>

#if defined(__linux__)
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if defined(__x86_64__)
#define SB_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SB_ARCH AUDIT_ARCH_AARCH64
#endif

/* LeakSanitizer stops the process with a ptrace(2)d clone to look for
   leaks at exit: sanitizer builds let both through */
#if defined(__SANITIZE_ADDRESS__)
#define SB_SANITIZER 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SB_SANITIZER 1
#endif
#endif

typedef struct { const char *name; long nr; } sb_call_t;

#define C(n) { #n, SYS_##n }

/* what a worker does: files (static files, sessions, uploads), sockets
   (the client, the parent, the key manager, a page's own connections),
   memory, time, signals and the timer */
static const sb_call_t sb_worker[] = {
    C(read), C(write), C(readv), C(writev), C(pread64), C(pwrite64),
    C(openat), C(close), C(fstat), C(newfstatat), C(lseek), C(faccessat),
    C(readlinkat), C(getdents64), C(mkdirat), C(unlinkat),
    C(ftruncate), C(fsync), C(fdatasync), C(fchmod), C(umask), C(getcwd),
    C(mmap), C(munmap), C(mprotect), C(brk), C(mremap), C(madvise),
    C(rt_sigaction), C(rt_sigprocmask), C(rt_sigreturn), C(sigaltstack),
    C(setitimer), C(getitimer), C(clock_gettime), C(clock_getres),
    C(gettimeofday), C(nanosleep), C(clock_nanosleep),
    C(getpid), C(getppid), C(gettid), C(getuid), C(geteuid), C(getgid),
    C(getegid), C(getgroups), C(prlimit64), C(getrusage), C(uname),
    C(sysinfo), C(exit), C(exit_group), C(kill), C(tgkill), C(futex),
    C(set_robust_list), C(get_robust_list), C(sched_yield),
    C(sched_getaffinity), C(ppoll), C(pselect6), C(accept), C(accept4),
    C(socket), C(connect), C(getsockname), C(getpeername), C(setsockopt),
    C(getsockopt), C(shutdown), C(recvfrom), C(sendto), C(recvmsg),
    C(sendmsg), C(socketpair), C(fcntl), C(dup), C(dup3), C(pipe2),
    C(ioctl), C(getrandom), C(sendfile), C(prctl), C(restart_syscall),
    C(set_tid_address),
#ifdef SYS_rseq
    C(rseq),
#endif
#ifdef SYS_statx
    C(statx),
#endif
#ifdef SYS_faccessat2
    C(faccessat2),
#endif
#ifdef SYS_renameat
    C(renameat),
#endif
#ifdef SYS_renameat2
    C(renameat2),
#endif
#ifdef SYS_open
    C(open), C(stat), C(lstat), C(access), C(readlink), C(mkdir), C(rmdir),
    C(unlink), C(rename), C(poll), C(select), C(dup2), C(pipe), C(time),
    C(alarm), C(getrlimit), C(getdents),
#endif
#ifdef SB_SANITIZER
    C(clone), C(ptrace), C(wait4), C(sched_getparam),
#endif
    { NULL, 0 }
};

/* CGI scripts: a worker that runs them forks and executes (in the
   script's directory); a new program sets up its thread pointer */
static const sb_call_t sb_exec[] = {
    C(clone), C(execve), C(wait4), C(waitid), C(setpgid), C(setsid),
    C(chdir), C(fchdir),
#ifdef SYS_arch_prctl
    C(arch_prctl),
#endif
#ifdef SYS_clone3
    C(clone3),
#endif
#ifdef SYS_fork
    C(fork), C(vfork),
#endif
#ifdef SYS_execveat
    C(execveat),
#endif
    { NULL, 0 }
};

/* the TLS key manager: its control socket, memory, randomness */
static const sb_call_t sb_keymgr[] = {
    C(recvmsg), C(sendmsg), C(sendto), C(ppoll), C(close), C(getppid),
    C(exit), C(exit_group), C(rt_sigreturn), C(rt_sigprocmask), C(brk),
    C(mmap), C(munmap), C(mremap), C(madvise), C(futex), C(getrandom),
    C(clock_gettime), C(restart_syscall), C(getpid), C(gettid),
#ifdef SYS_poll
    C(poll),
#endif
#ifdef SB_SANITIZER
    C(clone), C(ptrace), C(wait4), C(write), C(openat), C(read),
    C(sched_getparam), C(prctl), C(sigaltstack),
#endif
    { NULL, 0 }
};

/* calls a server process has no use for and an attacker does: the
   process is killed */
static const sb_call_t sb_kill[] = {
#ifndef SB_SANITIZER
    C(ptrace),
#endif
    C(process_vm_readv), C(process_vm_writev), C(mount), C(umount2),
    C(pivot_root), C(chroot), C(setuid), C(setgid), C(setreuid),
    C(setregid), C(setresuid), C(setresgid), C(setgroups), C(setfsuid),
    C(setfsgid), C(capset), C(init_module), C(finit_module),
    C(delete_module), C(kexec_load), C(bpf), C(perf_event_open), C(keyctl),
    C(add_key), C(request_key), C(unshare), C(setns), C(userfaultfd),
    C(personality), C(reboot), C(swapon), C(swapoff), C(acct),
    C(settimeofday), C(clock_settime), C(adjtimex), C(syslog), C(quotactl),
    C(open_by_handle_at), C(name_to_handle_at), C(fanotify_init),
    C(vhangup),
#ifdef SYS_kexec_file_load
    C(kexec_file_load),
#endif
#ifdef SYS_iopl
    C(iopl), C(ioperm),
#endif
    { NULL, 0 }
};

/* system calls that "sandbox_allow" may name, besides the lists above */
static const sb_call_t sb_extra[] = {
    C(fchown), C(fchownat), C(linkat), C(symlinkat), C(mknodat),
    C(inotify_init1), C(inotify_add_watch), C(inotify_rm_watch),
    C(epoll_create1), C(epoll_ctl), C(epoll_pwait), C(eventfd2),
    C(timerfd_create), C(timerfd_settime), C(timerfd_gettime), C(bind),
    C(listen), C(msync), C(mlock), C(munlock), C(flock), C(fallocate),
    C(utimensat), C(sched_setaffinity), C(memfd_create), C(copy_file_range),
    C(splice), C(tee),
#ifdef SYS_epoll_wait
    C(epoll_wait), C(link), C(symlink), C(chmod), C(chown),
#endif
    { NULL, 0 }
};

#undef C

static long sb_lookup(const sb_call_t *list, const char *name, size_t len)
{
    for(; list->name; ++list)
        if(strlen(list->name) == len && !strncmp(list->name, name, len))
            return list->nr;
    return -1;
}

static int sb_add(struct sock_filter *prog, size_t *n, size_t max, long nr,
        unsigned int action)
{
    if(*n + 2 > max)
        return ~0;
    prog[(*n)++] = (struct sock_filter)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int) nr, 0, 1);
    prog[(*n)++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, action);
    return 0;
}

static int sb_add_list(struct sock_filter *prog, size_t *n, size_t max,
        const sb_call_t *list, unsigned int action)
{
    for(; list->name; ++list)
        if(sb_add(prog, n, max, list->nr, action))
            return ~0;
    return 0;
}

/* build and load the filter: 'allow' (and 'exec' if set, and the names
   in 'extra') pass, sb_kill kills, anything else is EPERM */
static int sb_seccomp(const sb_call_t *allow, int exec, const char *extra)
{
    enum { MAX = 1024 };
    struct sock_filter prog[MAX];
    struct sock_fprog fprog;
    const char *p, *e;
    size_t n = 0;
    long nr;

#ifndef SB_ARCH
    u_unused_args(allow, exec, extra, prog, fprog, p, e, n, nr);
    warn("sandbox: no seccomp filter for this architecture");
    return 0;
#else
    /* another architecture's calls (e.g. 32-bit) would be other numbers */
    prog[n++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            offsetof(struct seccomp_data, arch));
    prog[n++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
            SB_ARCH, 1, 0);
    prog[n++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K,
            SECCOMP_RET_KILL_PROCESS);
    prog[n++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
    /* the x32 ABI: the same calls with bit 30 set */
    prog[n++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
            0x40000000, 0, 1);
    prog[n++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K,
            SECCOMP_RET_KILL_PROCESS);
#endif

    dbg_err_if(sb_add_list(prog, &n, MAX - 1, sb_kill,
                SECCOMP_RET_KILL_PROCESS));
    dbg_err_if(sb_add_list(prog, &n, MAX - 1, allow, SECCOMP_RET_ALLOW));
    if(exec)
        dbg_err_if(sb_add_list(prog, &n, MAX - 1, sb_exec, SECCOMP_RET_ALLOW));

    for(p = extra; p && *p; p = e)
    {
        p += strspn(p, " \t,");
        e = p + strcspn(p, " \t,");
        if(e == p)
            continue;
        if((nr = sb_lookup(sb_extra, p, (size_t) (e - p))) < 0 &&
                (nr = sb_lookup(sb_exec, p, (size_t) (e - p))) < 0)
            warn_err("sandbox_allow: %.*s is not a system call that can be "
                    "allowed (see doc/SANDBOX)", (int) (e - p), p);
        dbg_err_if(sb_add(prog, &n, MAX - 1, nr, SECCOMP_RET_ALLOW));
    }

    prog[n++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));

    fprog.len = (unsigned short) n;
    fprog.filter = prog;

    /* no setuid program can give the privileges back */
    dbg_err_sif(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    dbg_err_sif(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog));

    return 0;
err:
    return ~0;
#endif
}

/* check the names of a sandbox_allow list (at startup) */
int sandbox_check_allow(const char *extra)
{
    const char *p, *e;

    for(p = extra; p && *p; p = e)
    {
        p += strspn(p, " \t,");
        e = p + strcspn(p, " \t,");
        if(e > p && sb_lookup(sb_extra, p, (size_t) (e - p)) < 0 &&
                sb_lookup(sb_exec, p, (size_t) (e - p)) < 0)
            warn_err("sandbox_allow: %.*s is not a system call that can be "
                    "allowed (see doc/SANDBOX)", (int) (e - p), p);
    }
    return 0;
err:
    return ~0;
}

int sandbox_worker(int exec, const char *extra)
{
    return sb_seccomp(sb_worker, exec, extra);
}

int sandbox_keymgr(void)
{
    return sb_seccomp(sb_keymgr, 0, NULL);
}

#elif defined(__OpenBSD__)

#include <unistd.h>

/* untested: no OpenBSD machine in the test setup (doc/SANDBOX) */
int sandbox_check_allow(const char *extra)
{
    u_unused_args(extra);
    return 0;
}

int sandbox_worker(int exec, const char *extra)
{
    u_unused_args(extra);
    dbg_err_sif(pledge(exec ? "stdio rpath wpath cpath fattr inet unix dns "
                "sendfd recvfd proc exec" : "stdio rpath wpath cpath fattr "
                "inet unix dns sendfd recvfd", NULL));
    return 0;
err:
    return ~0;
}

int sandbox_keymgr(void)
{
    dbg_err_sif(pledge("stdio sendfd recvfd", NULL));
    return 0;
err:
    return ~0;
}

#else   /* no sandbox on this system */

int sandbox_check_allow(const char *extra)
{
    u_unused_args(extra);
    return 0;
}

int sandbox_worker(int exec, const char *extra)
{
    u_unused_args(exec, extra);
    return 0;
}

int sandbox_keymgr(void)
{
    return 0;
}

#endif
