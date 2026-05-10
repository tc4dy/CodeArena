#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char secret[64] = "FLAG{test}";

void vuln() {
    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
    printf("\n");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Leak: %p\n", secret);
    vuln();
    return 0;
}