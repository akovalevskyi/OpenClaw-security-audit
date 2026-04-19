#!/bin/bash
set -e
# OpenClaw Secure Backup Script (with Offsite Support)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/docker/openclaw_backups"
BACKUP_FILE="$BACKUP_DIR/openclaw_backup_$TIMESTAMP.tar.gz"
ENC_FILE="$BACKUP_FILE.gpg"
AUDIT_FILE="$BACKUP_DIR/openclaw_audit_$TIMESTAMP.log"
AUDIT_ENC="$AUDIT_FILE.gpg"
BASELINE_PREFIX="openclaw_security_baseline_"

if [ -z "$BACKUP_PASSPHRASE" ]; then
    if [ -r /root/.backup_passphrase ]; then
        BACKUP_PASSPHRASE="$(cat /root/.backup_passphrase)"
    else
        echo "ERROR: BACKUP_PASSPHRASE missing and /root/.backup_passphrase unreadable" >&2
        exit 1
    fi
fi

echo "[1/5] Creating backup of OpenClaw configurations..."
tar -czf "$BACKUP_FILE" -C /docker/openclaw-3g02/data .openclaw/openclaw.json .openclaw/agents/ .openclaw/credentials/ vault.sh vault_bridge.py vault_agent.py

echo "[2/5] Encrypting backup..."
gpg --batch --yes --symmetric --passphrase "$BACKUP_PASSPHRASE" -o "$ENC_FILE" "$BACKUP_FILE"
shred -u "$BACKUP_FILE"

echo "[3/5] Running OpenClaw Security Audit and encrypting log..."
docker exec openclaw-3g02-openclaw-1 openclaw security audit --deep > "$AUDIT_FILE" 2>&1 || echo "Audit warning: check logs"
gpg --batch --yes --symmetric --passphrase "$BACKUP_PASSPHRASE" -o "$AUDIT_ENC" "$AUDIT_FILE"
shred -u "$AUDIT_FILE"

echo "[4/5] Uploading to offsite..."
if rclone listremotes 2>/dev/null | grep -q '^b2-backup:'; then
    rclone copy "$ENC_FILE" b2-backup:openclaw-vault/ --log-file=/var/log/rclone-backup.log 2>&1
    rclone copy "$AUDIT_ENC" b2-backup:openclaw-vault/ --log-file=/var/log/rclone-backup.log 2>&1
    echo "Offsite upload complete."
else
    echo "WARNING: remote b2-backup not configured, skipping offsite upload." >&2
fi

echo "[5/5] Cleaning up backups older than 30 days (preserving baseline)..."
find "$BACKUP_DIR" -type f -mtime +30 ! -name "*${BASELINE_PREFIX}*" -delete

echo "Backup completed successfully!"
echo "Encrypted Archive: $ENC_FILE"
echo "Encrypted Audit: $AUDIT_ENC"
ok