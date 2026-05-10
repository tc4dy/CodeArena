import gdb

class HeapAnalysis(gdb.Command):
    """Dump heap chunks (glibc)."""
    def __init__(self):
        super(HeapAnalysis, self).__init__("heap_analyze", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        # find malloc hook
        malloc_hook = gdb.parse_and_eval("(void*)__malloc_hook")
        print(f"Malloc hook: {malloc_hook}")
        # dump arenas
        mp_ = gdb.parse_and_eval("main_arena")
        print(f"top chunk: {mp_['top']}")

class ROPGenerator(gdb.Command):
    """Generate simple ROP chain for x86_64."""
    def __init__(self):
        super(ROPGenerator, self).__init__("rop_gen", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        # pop rdi; ret gadget search
        gadgets = []
        # this would need one_gadget style, but stub:
        print("[*] Example ROP: pop rdi; /bin/sh; system")
        print("ROP chain: pop_rdi_addr + binsh_addr + system_addr")
        # here you would use ropgadget library
        print("Use `ropper` or `ROPgadget` tool for real chain.")

HeapAnalysis()
ROPGenerator()
print("[+] GDB script loaded: commands 'heap_analyze', 'rop_gen'")