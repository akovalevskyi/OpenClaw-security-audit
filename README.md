# OpenClaw Advanced Security Audit (v2.1)

A comprehensive security auditing and hardening framework for OpenClaw infrastructure, updated for 2026.x environment standards.

## New in v2.1
- **Resource Limit Enforcement:** Automated auditing of Docker CPU, Memory, and PID limits to prevent resource exhaustion and fork-bomb attacks.
- **Extended Docker Hardening:** Detection of AppArmor profiles, Init processes, and `no-new-privileges` flags.
- **Cloud-Audited Architecture:** Bypasses container sandbox restrictions via secure JSON API reporting.

## Features
- **One-Shot Fixes:** Dashboard and JSON API provide a concatenated prompt containing all detected vulnerabilities for instant AI remediation.
- **Host Hardening:** Port verification (2244), SSH restriction (AllowUsers root), and legacy user locking.
- **Docker Isolation:** Removal of `docker.sock`, integration with `bubblewrap` (bwrap), and `CAP_SYS_ADMIN` lifecycle management.
- **Network Security:** DOCKER-USER chain isolation, SSRF protection, and Private IP blocking.
- **Secure Backups:** GPG symmetric encryption (AES256) and automated offsite sync via rclone (Backblaze B2).
- **Web Audit Dashboard:** Real-time interactive security monitoring service (Flask) with JSON API.

## Security Checks Overview (34+ Parameters)

| Category | Check | Rationale |
|---|---|---|
| **Infrastructure** | SSH Port (2244) | Prevents automated brute-force attacks. |
| **Infrastructure** | SSH Password Auth | Forces use of cryptographic keys. |
| **Infrastructure** | Fail2ban / CrowdSec | Proactive threat intelligence and banning. |
| **Docker** | Socket Unmounted | Prevents container escape attacks. |
| **Docker** | Resource Limits | Prevents DoS and fork-bomb attacks (CPU/RAM/PIDs). |
| **Docker** | AppArmor / Init | Kernel-level protection and zombie process reaping. |
| **Sandboxing** | Bubblewrap (bwrap) | Unprivileged sandboxing for ALL agent executions. |
| **OpenClaw** | Session Isolation | `dmScope: per-channel-peer` for user privacy. |
| **OpenClaw** | Context Visibility | `allowlist` only to prevent prompt extraction. |
| **Maintenance** | GPG Backups | AES256 encryption for data at rest and in transit. |

## Components
- `openclaw_audit.py`: The primary audit engine for OpenClaw stacks.
- `skill/`: Gemini CLI Skill for autonomous security checks.
- `server/`: Flask-based Audit API and Web UI.
- `setup/`: Infrastructure hardening scripts and systemd services.

## Architecture: The "Cloud-Audit" Approach
In v2, the AI Agent no longer executes local bash scripts (restricted by `bubblewrap`). Instead:
1. The VPS host runs the audit scripts locally or via the Audit Server.
2. The Audit Server exposes a secure JSON endpoint.
3. The Agent uses the `web_fetch` tool to retrieve and report findings.

---
*Last Updated: April 27, 2026*
