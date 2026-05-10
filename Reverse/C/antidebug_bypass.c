#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <signal.h>

#ifdef __linux__
#include <sys/user.h>
#endif

// TLS callback function attribute
void __attribute__((constructor)) tls_anti_debug() {
    // This is called before main
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        printf("Detected debugger! (ptrace)\n");
        exit(1);
    }
}

void ptrace_check() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        printf("Debugger present (ptrace)\n");
        exit(1);
    }
}

void peb_check() {
#ifdef __linux__
    // Not directly applicable, this is for Windows. On Linux we can check /proc/self/status
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line+10);
                if (pid != 0) {
                    printf("TracerPid = %d (debugger attached)\n", pid);
                    exit(1);
                }
                break;
            }
        }
        fclose(fp);
    }
#endif
}

void timing_check() {
    clock_t start = clock();
    volatile int sum = 0;
    for (int i = 0; i < 1000000; i++) sum += i;
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    if (elapsed > 0.02) {
        printf("Timing anomaly, possible debugger\n");
        exit(1);
    }
}

// Bypass: patch the binary to remove ptrace check (nop out call)
// In real usage, use a binary patching tool.

int main() {
    printf("Starting protected program...\n");
    ptrace_check();
    peb_check();
    timing_check();
    printf("No debugger detected. Proceeding.\n");
    // your secret logic here
    return 0;
}