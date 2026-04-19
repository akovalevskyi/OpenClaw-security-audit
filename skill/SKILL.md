# OpenClaw Advanced Security Audit Skill

Expert instructions for verifying the security posture of the OpenClaw gateway and host infrastructure.

## Commands
- **Run Audit**: \`python3 scripts/audit_openclaw.py\` - executes a deep check across 28 security vectors.

## Verified Vectors:
1. **Infrastructure**: SSH (2244, AllowUsers), Fail2ban, UFW, Unattended-Upgrades status.
2. **Containerization**: Isolation (no-privileged), Resource Limits (Pids, CPU, RAM), Sandbox (bwrap).
3. **Networking**: DOCKER-USER iptables chain (DROP/LOG rules).
4. **Data Protection**: GPG-encrypted backups, Offsite replication (rclone).
5. **App Configuration**: trustedProxies, secret injection, rate limiting.

## Reference Files
- \`/root/openclaw_security_checklist.md\` - Master security checklist on the VPS.
- \`/root/backup_openclaw.sh\` - Hardened backup automation script.
