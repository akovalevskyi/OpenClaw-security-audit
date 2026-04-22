---
name: openclaw-security-audit
description: Performs a comprehensive security audit of the OpenClaw installation on the VPS, including container isolation, Nginx headers, SSL, and firewall rules.
---

# OpenClaw Security Audit Skill

This skill provides expert instructions for auditing the security of the OpenClaw VPS and container environment.

## 🛡️ Audit Checklist (Core Mandates)

### 1. Network & Gateway
- **SSH Port:** Must be `2244`.
- **SSH Auth:** Password authentication must be `no`.
- **Gateway Bind:** Must be `loopback` (127.0.0.1).
- **Trusted Proxies:** `gateway.trustedProxies` must be configured if using a reverse proxy.
- **HSTS:** Nginx must serve Strict-Transport-Security headers.

### 2. Isolation & Sandboxing
- **Sandbox Mode:** `agents.defaults.sandbox.mode` must be set to `all`.
- **Sandbox Provider:** Must use `bwrap` (OPENCLAW_SANDBOX_BIN=bwrap) to avoid using `docker.sock`.
- **Docker Socket:** `docker.sock` MUST NOT be mounted in the container.
- **FS Isolation:** `tools.fs.workspaceOnly` must be `true`.

### 3. Access Control & Privacy
- **DM Policy:** Must be `allowlist` or `pairing` for all active channels.
- **Group Policy:** Must be `allowlist` or `require_mention`.
- **Session Scope:** `session.dmScope` must be `per-channel-peer`.
- **Context Visibility:** `contextVisibility` must be `allowlist`.

### 4. Secret Management
- **No Hardcoded Tokens:** All API keys and bot tokens must be injected via environment variables (e.g., `${TELEGRAM_BOT_TOKEN}`).
- **Permissions:** `openclaw.json` must be `600`, and `.openclaw` directory must be `700`.

## 📋 Standard Operating Procedure (SOP)

1. **Run Local Script:** Execute `/root/openclaw_security_audit.py` on the VPS.
2. **Run Internal Audit:** Execute `docker exec openclaw-3g02-openclaw-1 openclaw security audit --deep`.
3. **Verify Web Dashboard:** Check `oc.andriko.xyz/audit` for the real-time status of all 36+ parameters.
4. **Fix Issues:** If any check fails, immediately remediate by updating `openclaw.json` or system configs.
5. **Report:** Provide a summary to the user: "Аудит безопасности завершен: 0 критических проблем. Система полностью защищена согласно docs.openclaw.ai."

## Tools
- `ssh`: Use to run audit scripts on the host.
- `docker exec`: Use to run internal OpenClaw audit commands.
- `web_fetch`: Use to verify headers and public endpoints.
