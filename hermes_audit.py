import subprocess
import json

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except:
        return ""

def run_audit():
    print("\033[1;36m--- HERMES AGENT ULTIMATE SECURITY AUDIT ---\033[0m")
    
    checks = []
    
    # 1. HOST
    checks.append(("SSH: Custom Port 2244", run_cmd("grep '^Port 2244' /etc/ssh/sshd_config") != ""))
    checks.append(("SSH: Password Auth Disabled", run_cmd("grep '^PasswordAuthentication no' /etc/ssh/sshd_config") != ""))
    checks.append(("OS: UFW Firewall Active", "active" in run_cmd("ufw status").lower()))
    checks.append(("OS: Fail2ban Service Active", run_cmd("systemctl is-active fail2ban") == "active"))

    # 2. DOCKER
    inspect = run_cmd("docker inspect Hermes-Agent")
    d = json.loads(inspect)[0] if inspect else {}
    hc = d.get('HostConfig', {})
    checks.append(("Docker: CAP_SYS_ADMIN Added", 'CAP_SYS_ADMIN' in (hc.get('CapAdd') or [])))
    checks.append(("Docker: No New Privileges", any('no-new-privileges' in opt for opt in (hc.get('SecurityOpt') or []))))
    checks.append(("Docker: AppArmor Profile set", any('apparmor' in opt for opt in (hc.get('SecurityOpt') or []))))
    checks.append(("Docker: Init Process enabled", hc.get('Init', False) == True))
    checks.append(("Docker: PIDs Limit set", hc.get('PidsLimit', 0) > 0))

    # 3. SANDBOX
    checks.append(("Sandbox: Bubblewrap Installed", run_cmd("docker exec Hermes-Agent which bwrap") != ""))
    
    redact_test = run_cmd("docker exec Hermes-Agent bash -c 'echo sk-ant-api03-1234567890abcdef1234567890abcdef | cat'")
    checks.append(("Sandbox: Secret Redactor Active", "[REDACTED]" in redact_test))
    
    ssrf_test = run_cmd("docker exec Hermes-Agent curl -s 169.254.169.254 --connect-timeout 1")
    checks.append(("Sandbox: SSRF Guard Intercepting", "blocked" in ssrf_test.lower() or ssrf_test == ""))
    
    # Config items
    config_yaml = run_cmd("docker exec Hermes-Agent cat /home/hermes/.hermes/config.yaml")
    checks.append(("Hermes: Tirith Enabled", "tirith_enabled: true" in config_yaml))
    checks.append(("Hermes: Tirith Fail-Closed", "tirith_fail_open: false" in config_yaml))
    checks.append(("Hermes: Private URL Block", "allow_private_urls: false" in config_yaml))
    
    # 4. SECRETS
    checks.append(("Secrets: .env Permissions (600/400)", run_cmd("stat -c %a /docker/hermes-agent/data/.env") in ["600", "400"]))
    checks.append(("Secrets: config.yaml Permissions (600/400)", run_cmd("stat -c %a /docker/hermes-agent/data/config.yaml") in ["600", "400"]))
    checks.append(("Secrets: Infisical MCP Configured", "infisical:" in config_yaml))

    passed = sum(1 for c in checks if c[1])
    total = len(checks)
    final_score = int((passed / total) * 100)
    
    color = "\033[1;32m" if final_score == 100 else "\033[1;31m"
    print(f"\n\033[1mSecurity Score: {color}{final_score}/100\033[0m")
    
    print(f"\n\033[1;33mAudit Log:\033[0m")
    for name, status in checks:
        icon = "\033[1;32m[PASS]\033[0m" if status else "\033[1;31m[FAIL]\033[0m"
        print(f"  {icon} {name}")

if __name__ == '__main__':
    run_audit()
