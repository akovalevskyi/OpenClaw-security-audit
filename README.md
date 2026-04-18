# OpenClaw Security Audit

A standalone, 1-click Python utility to perform a deep security audit of your [OpenClaw](https://openclaw.ai) installation on a VPS. It includes both a **CLI mode** and a beautifully animated **Web Dashboard**.

## Features

This tool automatically verifies your VPS and OpenClaw configuration against the official [OpenClaw Security Guidelines](https://docs.openclaw.ai/gateway/security):

- **Infrastructure Hardening**: SSH port configuration, password authentication limits, UFW firewall status, and Fail2ban.
- **Docker Security**: Checks for bubblewrap (bwrap) isolation, docker.sock unmounting, and DOCKER-USER iptables rules.
- **Secret Management**: Verifies the absence of hardcoded tokens and checks for vault scripts.
- **Application Security**: Rate limiting, mDNS status, tools.deny (bash/exec), and log redaction.
- **Web Security**: Checks for Nginx security headers (HSTS, XSS-Protection, X-Frame-Options).
- **Workspace Integrity**: Checks strict permissions for `.openclaw` directory (700) and `openclaw.json` (600).

## Requirements

- A Linux VPS running OpenClaw.
- Python 3.
- To use the Web Dashboard, you must have `flask` installed (`pip install flask`).

## Usage

Download the script to your VPS:

```bash
curl -O https://raw.githubusercontent.com/akovalevskyi/OpenClaw-security-audit/main/openclaw_audit.py
chmod +x openclaw_audit.py
```

### 1. CLI Mode (Terminal)

Run the script directly in your terminal for a fast, colorful text report:

```bash
python3 openclaw_audit.py
```

### 2. Web Dashboard Mode (Visual)

Spin up an interactive, animated web dashboard that streams the audit progress via Server-Sent Events (SSE):

```bash
python3 openclaw_audit.py --web
```

*By default, the dashboard will run on port `8021` (`http://<your-vps-ip>:8021`).*
*To specify a custom port, use: `python3 openclaw_audit.py --web --port 1234`*

If any checks fail, the dashboard will provide you with the exact prompt to copy and paste into Gemini CLI (or any other AI assistant) to automatically fix the vulnerability on your server.

## License

MIT License