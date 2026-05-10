BINARY="$1"
shift
BREAKPOINTS=("$@")

if [ ! -f "$BINARY" ]; then
    echo -e "\033[91m[-] Binary not found\033[0m"
    exit 1
fi

GDB_SCRIPT=$(mktemp /tmp/gdb_script_XXXXXX)
TRACE_LOG=$(mktemp /tmp/gdb_trace_XXXXXX)

# Generate GDB commands
cat > "$GDB_SCRIPT" << EOF
set pagination off
set logging file $TRACE_LOG
set logging on
file $BINARY
EOF

for bp in "${BREAKPOINTS[@]}"; do
    echo "break $bp" >> "$GDB_SCRIPT"
done

cat >> "$GDB_SCRIPT" << 'EOF'
# Define a hook to print registers and stack at each stop
define hook-stop
    printf "\n\033[33m[STOP] at %s\033[0m\n", $pc
    info registers
    x/10x $sp
    # optionally dump backtrace
    backtrace 5
end
run
# After run, continue until all breaks hit? We'll just continue forever
# Let's set a loop: continue on each stop, user can interrupt
echo \n\033[32m[*] GDB is running. Press Ctrl+C to stop.\033[0m\n
while 1
    continue
end
EOF

echo -e "\033[96m[*] Starting GDB with script: $GDB_SCRIPT\033[0m"
echo -e "\033[96m[*] Breakpoints: ${BREAKPOINTS[*]}\033[0m"

# Run GDB in background and capture its PID
gdb -x "$GDB_SCRIPT" &
GDB_PID=$!

# Wait a few seconds for GDB to start
sleep 2

# Now use a Python script to parse the trace log in real-time (optional)
# Or just tail the log file with colors
tail -f "$TRACE_LOG" | python3 -c "
import sys
import re
import time

colors = {
    'STOP': '\033[93m',
    'eax': '\033[92m',
    'pc': '\033[96m',
    'reset': '\033[0m'
}

for line in sys.stdin:
    if '[STOP]' in line:
        print(f\"{colors['STOP']}{line.strip()}{colors['reset']}\")
    elif re.search(r' (eax|ebx|ecx|edx|rax|rbx)=', line):
        print(f\"{colors['eax']}{line.strip()}{colors['reset']}\")
    else:
        print(line, end='')
    sys.stdout.flush()
" &

TAIL_PID=$!

# Trap Ctrl+C to kill GDB and temp files
cleanup() {
    kill $GDB_PID 2>/dev/null
    kill $TAIL_PID 2>/dev/null
    rm -f "$GDB_SCRIPT" "$TRACE_LOG"
    echo -e "\n\033[91m[*] Cleanup done.\033[0m"
    exit 0
}
trap cleanup SIGINT SIGTERM

# Wait for GDB to finish (it will run until user interrupts)
wait $GDB_PID
cleanup