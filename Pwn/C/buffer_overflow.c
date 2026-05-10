#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void win() {
    system("/bin/sh");
}

void vuln() {
    char buffer[64];
    char canary[8];
    FILE *f = fopen("/dev/urandom", "r");
    fread(canary, 1, 8, f);
    fclose(f);
    printf("Canary stored at %p\n", canary);
    printf("Enter data: ");
    gets(buffer);
    if (memcmp(buffer+64, canary, 8) != 0) {
        printf("Stack smashing detected\n");
        exit(1);
    }
    printf("Ok\n");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("Welcome to advanced buffer overflow\n");
    vuln();
    return 0;
}