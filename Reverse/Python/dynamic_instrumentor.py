#!/usr/bin/env python3

import sys
import argparse
import time
import threading

try:
    import frida
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
    from unicorn.x86_const import *
except ImportError:
    print("[!] Install: pip install frida-tools unicorn")
    sys.exit(1)

class DynamicInstrumentor:
    def __init__(self, target, is_process=False):
        self.target = target
        self.is_process = is_process
        self.session = None
        self.script = None

    def attach_frida(self, script_code):
        """Attach to process or binary and inject JS script."""
        try:
            if self.is_process:
                self.session = frida.attach(self.target)
            else:
                device = frida.get_local_device()
                pid = device.spawn([self.target])
                self.session = device.attach(pid)
                device.resume(pid)
            self.script = self.session.create_script(script_code)
            self.script.on('message', self.on_message)
            self.script.load()
            print("[+] Frida attached, waiting for events...")
            return True
        except Exception as e:
            print(f"[-] Frida error: {e}")
            return False

    def on_message(self, message, data):
        print(f"[Frida] {message}")

    def run_unicorn_emulate(self, code_bytes, start_addr, arch='x86', bits=32):
        """Emulate small shellcode or function using Unicorn."""
        if arch == 'x86':
            mode = UC_MODE_32 if bits == 32 else UC_MODE_64
            mu = Uc(UC_ARCH_X86, mode)
        else:
            raise NotImplemented("Only x86 for now")
        # Map memory
        mu.mem_map(start_addr & ~0xfff, 2*1024*1024)
        mu.mem_write(start_addr, code_bytes)
        # Set stack pointer
        if bits == 32:
            mu.reg_write(UC_X86_REG_ESP, start_addr + 0x1000)
        else:
            mu.reg_write(UC_X86_REG_RSP, start_addr + 0x1000)
        # Hook instructions to print
        def hook_code(mu, address, size, user_data):
            print(f"  Executed instruction at {hex(address)}")
            # optionally read registers
        mu.hook_add(UC_HOOK_CODE, hook_code)
        try:
            mu.emu_start(start_addr, start_addr + len(code_bytes))
            print("[+] Emulation finished")
            # Dump registers
            if bits == 32:
                eax = mu.reg_read(UC_X86_REG_EAX)
                print(f"EAX = {hex(eax)}")
            else:
                rax = mu.reg_read(UC_X86_REG_RAX)
                print(f"RAX = {hex(rax)}")
        except Exception as e:
            print(f"Emulation error: {e}")

def generate_frida_script():
    """Frida JavaScript for API call tracing."""
    return """
    Interceptor.attach(Module.findExportByName(null, "open"), {
        onEnter: function(args) {
            console.log("open called: path=" + Memory.readUtf8String(args[0]));
        }
    });
    Interceptor.attach(Module.findExportByName(null, "read"), {
        onEnter: function(args) {
            console.log("read fd=" + args[0] + " count=" + args[2]);
        }
    });
    // For Windows
    var kernel32 = Module.findBaseAddress("kernel32.dll");
    if (kernel32) {
        var createFile = Module.findExportByName("kernel32.dll", "CreateFileA");
        if (createFile) {
            Interceptor.attach(createFile, {
                onEnter: function(args) {
                    console.log("CreateFileA: " + Memory.readUtf8String(args[0]));
                }
            });
        }
    }
    """

def main():
    parser = argparse.ArgumentParser(description='Dynamic Instrumentation with Frida+Unicorn')
    parser.add_argument('target', help='Executable path or process name')
    parser.add_argument('--pid', action='store_true', help='Target is PID')
    parser.add_argument('--emulate', help='File containing raw code to emulate')
    args = parser.parse_args()

    di = DynamicInstrumentor(args.target, is_process=args.pid)
    if args.emulate:
        with open(args.emulate, 'rb') as f:
            code = f.read()
        di.run_unicorn_emulate(code, 0x1000, bits=64)
    else:
        script = generate_frida_script()
        if di.attach_frida(script):
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("[+] Stopping")
                di.session.detach()

if __name__ == '__main__':
    main()