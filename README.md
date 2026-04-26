# OpenClaw Advanced Security Audit (v2)

A comprehensive security auditing and hardening framework for OpenClaw infrastructure, updated for OpenClaw 2026.x Beta.

## New in v2
- **Cloud-Audited Architecture:** Agents now use `web_fetch` to retrieve reports via a secure JSON API, bypassing container sandbox restrictions.
- **One-Shot Remediation:** Unified Fix Prompt for instant AI-driven security hardening.
- **Enhanced 2026.x Schema Support:** Full awareness of `session.dmScope`, `contextVisibility`, and `compaction` settings.
- **External Sandboxing:** Detection and support for `bubblewrap` (bwrap) isolation without the need for `docker.sock`.
- **Daily Audit Notifications:** Automated daily checks with Telegram reporting.

## Features
- **One-Shot Fixes:** Dashboard and JSON API provide a concatenated prompt containing all detected vulnerabilities and environment context for instant fixing.
- **Host Hardening:** Port verification (2244), SSH restriction (AllowUsers root), and legacy user locking.
- **Docker Isolation:** Removal of `docker.sock` and integration with `bubblewrap`.
- **Network Security:** DOCKER-USER chain isolation and Trusted Proxy configuration.
- **Secure Backups:** GPG symmetric encryption (AES256) and automated offsite sync via rclone (Backblaze B2).
- **Web Audit Dashboard:** Real-time interactive security monitoring service (Flask) with JSON API.

## Security Checks Overview (34+ Parameters)

The following core checks are performed to ensure maximum protection:

| Category | Check | Rationale |
|---|---|---|
| **Infrastructure** | SSH Port (2244) | Prevents automated brute-force attacks. |
| **Infrastructure** | SSH Password Auth | Forces use of cryptographic keys. |
| **Infrastructure** | Fail2ban / CrowdSec | Proactive threat intelligence and banning. |
| **Docker** | Socket Unmounted | Prevents container escape attacks. |
| **Docker** | Bubblewrap (bwrap) | Unprivileged sandboxing for AI agents. |
| **OpenClaw** | Sandbox Mode: All | Forces isolation for all agent executions. |
| **OpenClaw** | Session Isolation | `dmScope: per-channel-peer` for user privacy. |
| **OpenClaw** | Context Visibility | `allowlist` only to prevent prompt extraction. |
| **OpenClaw** | Workspace FS | Restricts agents to dedicated working directories. |
| **OpenClaw** | Throttling | Rate limiting and history compaction safeguard. |
| **Gateway** | Local Mode | Personal Assistant trust model (Local-only bind). |
| **Gateway** | Trusted Proxies | Prevents IP spoofing when behind Traefik/Nginx. |
| **Headers** | HSTS / XFO / XCTO | Protection against MitM and Clickjacking. |
| **Maintenance** | GPG Backups | AES256 encryption for data at rest and in transit. |

## Components
- `skill/`: OpenClaw/Gemini Skill for autonomous security checks via Cloud API.
- `server/`: Flask-based Audit API (`/audit/json`) and Web UI.
- `setup/`: Infrastructure hardening scripts and systemd services.

## Architecture: The "Cloud-Audit" Approach
In v2, the AI Agent no longer executes local bash scripts (which is restricted by `bubblewrap`). Instead:
1. The VPS host runs the `openclaw_security_audit.py` script locally or via the Audit Server.
2. The Audit Server exposes a secure JSON endpoint.
3. The Agent uses the `web_fetch` tool to retrieve and report findings.
This provides the best balance between security (isolated agent) and visibility (detailed auditing).

---
*Last Updated: April 22, 2026*
