#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct chunk {
    char data[32];
    void (*func)(char*);
};

void legit(char *s) {
    printf("Legit: %s\n", s);
}

void win(char *s) {
    system("/bin/sh");
}

int main() {
    struct chunk *c = malloc(sizeof(struct chunk));
    c->func = legit;
    strcpy(c->data, "hello");
    free(c);
    // UAF: after free, we can still use c
    struct chunk *d = malloc(sizeof(struct chunk));
    // d gets same address
    memset(d, 0, sizeof(struct chunk));
    // trigger
    c->func(c->data);
    // overflow data
    strcpy(d->data, "/bin/sh");
    d->func = win;
    c->func(c->data);
    return 0;
}