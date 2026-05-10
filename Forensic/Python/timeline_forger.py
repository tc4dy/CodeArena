#!/usr/bin/env python3

import os
import sys
import re
import csv
import argparse
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

try:
    import pytz
except ImportError:
    print("[!] Install pytz: pip install pytz")
    sys.exit(1)

def parse_syslog_line(line):
    """Extract timestamp from syslog format: MMM DD HH:MM:SS"""
    months = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
    pattern = r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})'
    m = re.match(pattern, line)
    if m:
        month = months.get(m.group(1), 1)
        day = int(m.group(2))
        time_str = m.group(3)
        now = datetime.now()
        year = now.year
        dt = datetime(year, month, day, *map(int, time_str.split(':')))
        # If the date is in the future, subtract a year
        if dt > now:
            dt = datetime(year-1, month, day, *map(int, time_str.split(':')))
        return dt.isoformat()
    return None

def parse_apache_log(line):
    """Apache common log format: [DD/MMM/YYYY:HH:MM:SS +0000]"""
    pattern = r'\[(\d{2}/\w{3}/\d{4}):(\d{2}:\d{2}:\d{2}) \+\d{4}\]'
    m = re.search(pattern, line)
    if m:
        months = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
        day, mon, year = m.group(1).split('/')
        month = months.get(mon, 1)
        dt = datetime(int(year), month, int(day), *map(int, m.group(2).split(':')))
        return dt.isoformat()
    return None

def parse_epoch(epoch_str):
    """Convert epoch string to ISO"""
    try:
        epoch = int(epoch_str)
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except:
        return None

def detect_timestomping(filepath):
    """Check if file's MACB timestamps are inconsistent"""
    stat = os.stat(filepath)
    atime = stat.st_atime
    mtime = stat.st_mtime
    ctime = stat.st_ctime
    # If access time is older than modify time, suspicious
    if atime > mtime + 3600:
        return True
    # If ctime is far from mtime (possible touch)
    if abs(ctime - mtime) > 86400:
        return True
    return False

def main():
    parser = argparse.ArgumentParser(description='Timeline Forger & Timestomping Detector')
    parser.add_argument('log_dir', nargs='?', default='/var/log', help='Directory containing logs')
    parser.add_argument('--output', '-o', default='timeline.csv', help='Output CSV file')
    parser.add_argument('--scan-files', action='store_true', help='Scan files for timestomping')
    args = parser.parse_args()

    timeline = []
    log_dir = Path(args.log_dir)

    # Collect all log files
    log_files = list(log_dir.rglob('*.log')) + list(log_dir.rglob('auth.log')) + \
                list(log_dir.rglob('syslog')) + list(log_dir.rglob('secure')) + \
                list(log_dir.rglob('messages')) + list(log_dir.rglob('access.log')) + \
                list(log_dir.rglob('error.log'))

    for lf in log_files:
        try:
            with open(lf, 'r', errors='ignore') as f:
                for line in f:
                    ts = parse_syslog_line(line) or parse_apache_log(line)
                    if ts:
                        timeline.append([ts, str(lf), line.strip()])
        except:
            continue

    # Write CSV
    with open(args.output, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['timestamp', 'source', 'raw_line'])
        writer.writerows(timeline)

    print(f"[+] Timeline saved to {args.output} ({len(timeline)} entries)")

    if args.scan_files:
        print("\n[*] Scanning for timestomping...")
        for root, dirs, files in os.walk('/'):
            for f in files:
                full = os.path.join(root, f)
                try:
                    if detect_timestomping(full):
                        print(f"[!!] Inconsistent timestamps: {full}")
                except:
                    pass

if __name__ == '__main__':
    main()