#!/bin/bash
set -e
# OpenClaw & Hermes Surgical Identity Backup Script
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/docker/openclaw_backups"
BASELINE_PREFIX="openclaw_security_baseline_"

# 1. Initialize Passphrase
if [ -z "$BACKUP_PASSPHRASE" ]; then
    if [ -r /root/.backup_passphrase ]; then
        BACKUP_PASSPHRASE="$(cat /root/.backup_passphrase)"
    else
        echo "ERROR: BACKUP_PASSPHRASE missing" >&2
        exit 1
    fi
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# --- OPENCLAW CHUNK (Personality & State Only) ---
OC_FILE="$BACKUP_DIR/openclaw_backup_$TIMESTAMP.tar.gz"
OC_ENC="$OC_FILE.gpg"
echo "[1/6] Creating OpenClaw surgical backup..."
# We backup: main config, agents (personality/sessions), memory, skills, identity, and credentials
tar -czf "$OC_FILE" -C /docker/openclaw-3g02/data     .openclaw/openclaw.json     .openclaw/agents/     .openclaw/identity/     .openclaw/memory/     .openclaw/skills/     .openclaw/credentials/     .openclaw/vertex_key.json     vault.sh     vault_bridge.py 2>/dev/null || true

gpg --batch --yes --symmetric --passphrase "$BACKUP_PASSPHRASE" -o "$OC_ENC" "$OC_FILE"
shred -u "$OC_FILE"

# --- HERMES CHUNK (Personality & State Only) ---
HERMES_FILE="$BACKUP_DIR/hermes_backup_$TIMESTAMP.tar.gz"
HERMES_ENC="$HERMES_FILE.gpg"
echo "[2/6] Creating Hermes surgical backup..."
# We backup: config, soul, state DB, sessions, skills, auth
tar -czf "$HERMES_FILE" -C /docker/hermes-agent/data     config.yaml     SOUL.md     state.db     auth.json     .env     sessions/     skills/     memories/ 2>/dev/null || true

gpg --batch --yes --symmetric --passphrase "$BACKUP_PASSPHRASE" -o "$HERMES_ENC" "$HERMES_FILE"
shred -u "$HERMES_FILE"

# --- AUDIT LOGS ---
AUDIT_FILE="$BACKUP_DIR/security_audit_$TIMESTAMP.log"
AUDIT_ENC="$AUDIT_FILE.gpg"
echo "[3/6] Running Security Audits..."
echo "--- OpenClaw Audit ---" > "$AUDIT_FILE"
docker exec openclaw-3g02-openclaw-1 openclaw security audit --deep >> "$AUDIT_FILE" 2>&1 || true
gpg --batch --yes --symmetric --passphrase "$BACKUP_PASSPHRASE" -o "$AUDIT_ENC" "$AUDIT_FILE"
shred -u "$AUDIT_FILE"

# --- OFFSITE UPLOAD ---
echo "[4/6] Uploading to Offsite (Backblaze B2)..."
if rclone listremotes 2>/dev/null | grep -q '^b2-backup:'; then
    rclone copy "$OC_ENC" b2-backup:openclaw-vault/ --log-file=/var/log/rclone-backup.log
    rclone copy "$AUDIT_ENC" b2-backup:openclaw-vault/ --log-file=/var/log/rclone-backup.log
fi

if rclone listremotes 2>/dev/null | grep -q '^b2-hermes:'; then
    rclone copy "$HERMES_ENC" b2-hermes:hermes-vault/ --log-file=/var/log/rclone-backup.log
    echo "Hermes offsite upload complete."
fi

# --- CLEANUP ---
echo "[5/6] Cleaning up old local backups (>30 days)..."
find "$BACKUP_DIR" -type f -mtime +30 ! -name "*${BASELINE_PREFIX}*" -delete

echo "[6/6] Backup process completed successfully!"
