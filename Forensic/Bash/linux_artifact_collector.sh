#!/bin/bash

OUTPUT_DIR="linux_forensics_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
echo "[+] Collecting Linux artifacts into $OUTPUT_DIR"

# System info
uname -a > "$OUTPUT_DIR/uname.txt"
cat /etc/os-release > "$OUTPUT_DIR/os-release.txt" 2>/dev/null
uptime > "$OUTPUT_DIR/uptime.txt"

# User accounts
cat /etc/passwd > "$OUTPUT_DIR/passwd.txt"
cat /etc/shadow > "$OUTPUT_DIR/shadow.txt" 2>/dev/null
cat /etc/group > "$OUTPUT_DIR/group.txt"
last -n 100 > "$OUTPUT_DIR/last_logins.txt"
lastlog > "$OUTPUT_DIR/lastlog.txt"

# Command history (for current user and home dirs)
history > "$OUTPUT_DIR/current_user_history.txt" 2>/dev/null
for user_home in /home/* /root; do
    if [ -f "$user_home/.bash_history" ]; then
        cp "$user_home/.bash_history" "$OUTPUT_DIR/$(basename "$user_home")_bash_history.txt"
    fi
    if [ -f "$user_home/.zsh_history" ]; then
        cp "$user_home/.zsh_history" "$OUTPUT_DIR/$(basename "$user_home")_zsh_history.txt"
    fi
done

# Running processes
ps auxwf > "$OUTPUT_DIR/ps_auxwf.txt"
ps auxwf --forest > "$OUTPUT_DIR/ps_tree.txt"
lsof -n > "$OUTPUT_DIR/lsof.txt" 2>/dev/null
netstat -tulpn > "$OUTPUT_DIR/netstat.txt" 2>/dev/null
ss -tulpn > "$OUTPUT_DIR/ss.txt" 2>/dev/null

# Cron jobs
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l > "$OUTPUT_DIR/cron_${user}.txt" 2>/dev/null
done
cp /etc/crontab "$OUTPUT_DIR/crontab_system.txt" 2>/dev/null
ls -la /etc/cron.* > "$OUTPUT_DIR/cron_dirs.txt" 2>/dev/null

# Recently modified files (last 7 days)
find / -type f -mtime -7 2>/dev/null | head -500 > "$OUTPUT_DIR/recent_files_7days.txt"

# SSH configuration and keys
cp -r /etc/ssh "$OUTPUT_DIR/ssh_config" 2>/dev/null
cp -r ~/.ssh "$OUTPUT_DIR/current_user_ssh" 2>/dev/null

# Logs (only last 10000 lines to save space)
for log in /var/log/syslog /var/log/auth.log /var/log/secure /var/log/messages /var/log/apache2/access.log /var/log/nginx/access.log; do
    if [ -f "$log" ]; then
        tail -10000 "$log" > "$OUTPUT_DIR/$(basename "$log")_tail.txt"
    fi
done

# Memory dump (simple, using /proc/kcore - needs root)
if [ "$EUID" -eq 0 ]; then
    echo "[*] Dumping memory (may take a while)..."
    dd if=/proc/kcore of="$OUTPUT_DIR/memory_dump.raw" bs=1M count=512 status=progress 2>/dev/null
else
    echo "[!] Skipping memory dump (not root)"
fi

# Generate hash of all collected files (integrity)
cd "$OUTPUT_DIR" || exit
find . -type f -exec sha256sum {} \; > hashes.txt
cd - > /dev/null

echo "[+] Collection finished. Archive with: tar czf $OUTPUT_DIR.tar.gz $OUTPUT_DIR"