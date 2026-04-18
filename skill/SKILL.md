---
name: openclaw-security-audit
description: Performs a comprehensive security audit of the OpenClaw installation on the VPS, including container isolation, Nginx headers, SSL, and firewall rules.
---

# OpenClaw Security Audit

Use this skill to verify the security posture of the OpenClaw gateway and its infrastructure.

## Workflow

1. **Run the Audit Script**: Execute the bundled Python script to perform automated checks on the VPS.
   ```bash
   python3 scripts/audit_openclaw.py
   ```

2. **Analyze Results**:
   - **Internal Audit**: Review the output from `openclaw security audit`. Pay attention to CRITICAL or WARN items.
   - **Nginx Headers**: Ensure HSTS, X-Frame-Options, and other security headers are present for `oc.andriko.xyz`.
   - **Firewall**: Verify that the `DOCKER-USER` chain effectively isolates the container from external traffic on `eth0`.
   - **Permissions**: Confirm that `.openclaw` (700) and `openclaw.json` (600) have strict permissions.

3. **Remediation**: If any checks fail, propose fixes based on the [OpenClaw Security Documentation](https://docs.openclaw.ai/gateway/security).

## Resources

- `scripts/audit_openclaw.py`: Automates SSH connection and security verification steps.
