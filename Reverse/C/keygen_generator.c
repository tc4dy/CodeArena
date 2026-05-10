#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_NAME 256

unsigned int calculate_checksum(const char *s) {
    unsigned int cs = 0xDEADBEEF;
    for (int i = 0; s[i]; i++) {
        cs ^= (cs << 5) + (cs >> 2) + (unsigned char)s[i];
    }
    return cs;
}

void generate_serial(const char *name, char *out_serial) {
    unsigned int cs = calculate_checksum(name);
    // Format as hex string with lowercase
    sprintf(out_serial, "%08X", cs);
    // Additional obfuscation: swap nibbles every second char
    for (int i = 0; i < 8; i += 2) {
        if (out_serial[i] && out_serial[i+1]) {
            char tmp = out_serial[i];
            out_serial[i] = out_serial[i+1];
            out_serial[i+1] = tmp;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <username>\n", argv[0]);
        return 1;
    }
    char serial[32];
    generate_serial(argv[1], serial);
    printf("Serial for user '%s': %s\n", argv[1], serial);
    return 0;
}