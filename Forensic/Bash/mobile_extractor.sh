#!/bin/bash

set -e

OUTPUT_BASE="mobile_forensics_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_BASE"

echo "=== Mobile Extractor ==="
echo "Output directory: $OUTPUT_BASE"

# Detect connected device (adb for Android, idevice for iOS)
if command -v adb &>/dev/null && adb devices | grep -q "device$"; then
    echo "[+] Android device detected"
    DEVICE_TYPE="android"
    BACKUP_DIR="$OUTPUT_BASE/android_backup"
    mkdir -p "$BACKUP_DIR"
    # Pull /data/data (requires root, but try anyway)
    adb backup -apk -shared -all -f "$BACKUP_DIR/backup.ab"
    echo "   Backup saved to $BACKUP_DIR/backup.ab"
    # Convert AB backup to tar
    dd if="$BACKUP_DIR/backup.ab" bs=4K skip=24 | zcat > "$BACKUP_DIR/backup.tar" 2>/dev/null || true
    # Extract important databases
    mkdir -p "$BACKUP_DIR/databases"
    find "$BACKUP_DIR" -name "*.db" -o -name "*.sqlite" | while read db; do
        cp "$db" "$BACKUP_DIR/databases/"
        echo "   Copied DB: $db"
        # Try to parse WhatsApp, Telegram, Signal (simplified)
        if [[ "$db" == *"whatsapp"* ]]; then
            sqlite3 "$db" "SELECT * FROM messages LIMIT 10;" > "$BACKUP_DIR/databases/whatsapp_messages.txt" 2>/dev/null || true
        fi
    done
elif command -v ideviceinfo &>/dev/null; then
    echo "[+] iOS device detected"
    DEVICE_TYPE="ios"
    BACKUP_DIR="$OUTPUT_BASE/ios_backup"
    mkdir -p "$BACKUP_DIR"
    # Create encrypted backup
    idevicebackup2 backup --full "$BACKUP_DIR"
    echo "   iOS backup saved to $BACKUP_DIR"
    # Extract manifest and info
    if [ -f "$BACKUP_DIR/Manifest.plist" ]; then
        plutil -convert json "$BACKUP_DIR/Manifest.plist" -o "$BACKUP_DIR/manifest.json" 2>/dev/null || true
    fi
else
    echo "[-] No device found. Please connect Android (adb) or iOS (idevicebackup2)."
    exit 1
fi

# General media extraction (photos, videos, audio)
MEDIA_DIR="$OUTPUT_BASE/media"
mkdir -p "$MEDIA_DIR"
# For Android: pull DCIM and Pictures
if [ "$DEVICE_TYPE" = "android" ]; then
    adb pull /sdcard/DCIM "$MEDIA_DIR/DCIM" 2>/dev/null || true
    adb pull /sdcard/Pictures "$MEDIA_DIR/Pictures" 2>/dev/null || true
    adb pull /sdcard/WhatsApp/Media "$MEDIA_DIR/WhatsApp" 2>/dev/null || true
elif [ "$DEVICE_TYPE" = "ios" ]; then
    # Use ifuse to mount (requires root/fuse)
    if command -v ifuse &>/dev/null; then
        MOUNT_POINT="$OUTPUT_BASE/ios_mount"
        mkdir -p "$MOUNT_POINT"
        ifuse "$MOUNT_POINT"
        cp -r "$MOUNT_POINT/DCIM" "$MEDIA_DIR/" 2>/dev/null || true
        fusermount -u "$MOUNT_POINT"
    else
        echo "Install ifuse to extract iOS media"
    fi
fi

# Generate simple report
echo "Device: $DEVICE_TYPE" > "$OUTPUT_BASE/report.txt"
echo "Backup location: $BACKUP_DIR" >> "$OUTPUT_BASE/report.txt"
echo "Media location: $MEDIA_DIR" >> "$OUTPUT_BASE/report.txt"
echo "Timestamp: $(date)" >> "$OUTPUT_BASE/report.txt"

echo "[+] Mobile extraction complete. Output: $OUTPUT_BASE"