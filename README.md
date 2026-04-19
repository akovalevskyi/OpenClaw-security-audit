# OpenClaw Advanced Security Audit

A comprehensive security auditing and hardening framework for OpenClaw infrastructure.

## Features
- **Host Hardening:** Port verification, SSH restriction (AllowUsers root), and legacy user locking.
- **Docker Isolation:** PidsLimit enforcement, privileged mode removal, and bubblewrap (bwrap) integration.
- **Network Security:** DOCKER-USER chain isolation with logging to prevent UFW bypass.
- **Secure Backups:** GPG symmetric encryption (AES256) and automated offsite sync via rclone (Backblaze B2).
- **Web Audit Dashboard:** Real-time interactive security monitoring service (Flask).

## Security Checks Overview

The following 28 checks are performed to ensure maximum protection:

| # | Check Name | Rationale / Why it's needed |
|---|---|---|
| 1 | **SSH Port (2244)** | Prevents automated brute-force attacks by using a non-standard port. |
| 2 | **SSH Password Auth** | Forces use of cryptographic keys, making unauthorized access much harder. |
| 3 | **SSH AllowUsers root** | Restricts SSH access exclusively to root, preventing entry via less-secure accounts. |
| 4 | **Fail2ban Jails** | Automatically bans IPs showing malicious signs (failed logins, bot scanning). |
| 5 | **UFW Status** | Ensures the host-level firewall is active to block unauthorized incoming traffic. |
| 6 | **DOCKER-USER Isolation** | Prevents Docker from bypassing UFW rules via its own iptables chains. |
| 7 | **Docker Socket Unmounted** | Prevents container escape attacks where a compromised container controls the host. |
| 8 | **Bubblewrap (bwrap)** | Provides a secondary layer of unprivileged sandboxing for individual AI agents. |
| 9 | **Vault Secret Management** | Uses dynamic injection to keep sensitive keys out of plaintext files. |
| 10 | **No Hardcoded Tokens** | Ensures keys are managed via environment variables or secret managers. |
| 11 | **Sandbox Mode: All** | Forces all AI agents to run inside an isolated sandbox by default. |
| 12 | **Dangerous Tools Denied** | Blocks agents from using dangerous tools like \`exec\` or \`bash\` in public APIs. |
| 13 | **Rate Limiting** | Protects the gateway from DoS attacks and API brute-forcing. |
| 14 | **mDNS Disabled** | Reduces network footprint and prevents local service discovery leakage. |
| 15 | **Sensitive Logs Redacted** | Prevents API keys and private data from appearing in application logs. |
| 16 | **CrowdSec Engine** | Provides real-time threat intelligence to block globally known malicious IPs. |
| 17 | **SSH Alert Bot** | Sends immediate notifications on every successful SSH login attempt. |
| 18 | **Dir Permissions** | Ensures \`.openclaw\` directory is accessible only by the owner (700). |
| 19 | **File Permissions** | Ensures \`openclaw.json\` is readable only by the owner (600). |
| 20 | **HSTS Header** | Forces browsers to use HTTPS, preventing man-in-the-middle attacks. |
| 21 | **XCTO Header** | Prevents MIME-type sniffing, stopping certain cross-site scripting (XSS) attacks. |
| 22 | **XFO Header** | Prevents site from being rendered in an iframe (Clickjacking protection). |
| 23 | **XXSS Header** | Enables the browser's built-in XSS protection mechanism. |
| 24 | **Ubuntu User Locked** | Disables the default user account to remove a common entry point for attackers. |
| 25 | **Kernel Up-to-Date** | Ensures critical security patches for the Linux kernel are applied and active. |
| 26 | **GPG Backup Encryption** | Protects archives with AES256 encryption, making stolen data unreadable. |
| 27 | **Offsite rclone B2** | Replicates encrypted backups to cloud storage for disaster recovery. |
| 28 | **Internal OpenClaw Audit** | Runs the native health check to ensure internal module integrity. |

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
