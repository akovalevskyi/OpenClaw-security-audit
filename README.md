# OpenClaw Advanced Security Audit

A comprehensive security auditing and hardening framework for OpenClaw infrastructure.

## Features
- **Host Hardening:** Port verification, SSH restriction (AllowUsers root), and legacy user locking.
- **Docker Isolation:** PidsLimit enforcement, privileged mode removal, and bubblewrap (bwrap) integration.
- **Network Security:** DOCKER-USER chain isolation with logging to prevent UFW bypass.
- **Secure Backups:** GPG symmetric encryption (AES256) and automated offsite sync via rclone (Backblaze B2).
- **Web Audit Dashboard:** Real-time interactive security monitoring service (Flask).

## Components
- \`skill/\`: Gemini CLI Skill for autonomous security checks.
- \`server/\`: Flask-based Audit API and Web UI.
- \`setup/\`: Infrastructure hardening scripts and systemd services.

## Prerequisites
1. \`rclone\` configured with a remote named \`b2-backup\`.
2. \`gpg\` installed with a passphrase stored in \`/root/.backup_passphrase\`.
3. \`docker-security-rules.service\` installed for firewall persistence.

---
*Last Updated: April 19, 2026*
