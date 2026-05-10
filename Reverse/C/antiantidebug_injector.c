#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>

// Original function pointers
static long (*real_ptrace)(enum __ptrace_request request, pid_t pid, void *addr, void *data) = NULL;
static FILE* (*real_fopen)(const char *path, const char *mode) = NULL;
static int (*real_open)(const char *path, int flags, mode_t mode) = NULL;
static int (*real_clock_gettime)(clockid_t clk_id, struct timespec *tp) = NULL;
static void (*real_exit)(int status) = NULL;

// ptrace hook: always return 0 for PTRACE_TRACEME
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {
    if (!real_ptrace)
        real_ptrace = (long (*)(enum __ptrace_request, pid_t, void*, void*)) dlsym(RTLD_NEXT, "ptrace");
    if (request == PTRACE_TRACEME) {
        fprintf(stderr, "[ANTIANTI] ptrace(PTRACE_TRACEME) intercepted -> returning 0\n");
        return 0;
    }
    return real_ptrace(request, pid, addr, data);
}

// Helper: filter /proc/self/status to hide TracerPid
static void filter_status_file(FILE *fp) {
    rewind(fp);
    char line[512];
    FILE *tmp = tmpfile();
    if (!tmp) return;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            fprintf(tmp, "TracerPid:\t0\n");
            continue;
        }
        fputs(line, tmp);
    }
    rewind(tmp);
    // replace fp content (can't easily, but we can redirect reads)
    // Instead, we will just read from tmp for subsequent reads.
    // This is a simplified approach; full solution would replace FILE* internals.
    // For demo, we close and reopen with overwritten content.
    long pos = ftell(tmp);
    fclose(fp);
    fp = freopen("/dev/null", "r", fp); // not perfect
}

// fopen hook: if opening /proc/self/status, return filtered version
FILE* fopen(const char *path, const char *mode) {
    if (!real_fopen) real_fopen = (FILE* (*)(const char*, const char*)) dlsym(RTLD_NEXT, "fopen");
    if (path && strcmp(path, "/proc/self/status") == 0) {
        fprintf(stderr, "[ANTIANTI] fopen /proc/self/status intercepted, applying filter\n");
        FILE *orig = real_fopen(path, mode);
        if (orig) filter_status_file(orig);
        return orig;
    }
    return real_fopen(path, mode);
}

// open hook (low-level)
int open(const char *path, int flags, mode_t mode) {
    if (!real_open) real_open = (int (*)(const char*, int, mode_t)) dlsym(RTLD_NEXT, "open");
    if (path && strcmp(path, "/proc/self/status") == 0) {
        fprintf(stderr, "[ANTIANTI] open /proc/self/status intercepted\n");
        int fd = real_open(path, flags, mode);
        if (fd != -1) {
            // Read all content, filter, write back (complex)
            // For brevity, we skip full implementation, but idea clear.
        }
        return fd;
    }
    return real_open(path, flags, mode);
}

// clock_gettime: add small jitter (max 10ms) to fool timing checks
int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    if (!real_clock_gettime) real_clock_gettime = (int (*)(clockid_t, struct timespec*)) dlsym(RTLD_NEXT, "clock_gettime");
    int ret = real_clock_gettime(clk_id, tp);
    if (ret == 0 && tp) {
        // add up to 10ms jitter
        long ns_jitter = (rand() % 10000000);
        tp->tv_nsec += ns_jitter;
        if (tp->tv_nsec >= 1000000000) {
            tp->tv_sec++;
            tp->tv_nsec -= 1000000000;
        }
    }
    return ret;
}

// exit hook: prevent exit(1) if called from anti-debug
void exit(int status) {
    if (!real_exit) real_exit = (void (*)(int)) dlsym(RTLD_NEXT, "exit");
    // If status is non-zero, assume anti-debug triggered; ignore?
    if (status != 0) {
        fprintf(stderr, "[ANTIANTI] exit(%d) intercepted - blocking to continue debugging\n", status);
        // Instead of exiting, longjmp or just return (but we can't return from exit)
        // We'll force a infinite pause or raise SIGSTOP to let debugger attach
        raise(SIGSTOP);
        return;
    }
    real_exit(status);
}

// Constructor: initialize rand
__attribute__((constructor)) void init() {
    srand(time(NULL));
    fprintf(stderr, "[ANTIANTI] LD_PRELOAD anti-anti-debug loaded.\n");
}