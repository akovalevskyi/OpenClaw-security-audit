import json
import subprocess
import sys
import os

def run_ssh(host, command):
    # Using the standard SSH setup from config
    full_cmd = f"ssh -p 2244 root@{host} \"{command}\""
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode

def main():
    # Load config
    config_path = "/data/data/com.termux/files/home/openclaw_config.json"
    if not os.path.exists(config_path):
        print(f"Error: {config_path} not found.")
        sys.exit(1)
        
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Use the local tailscale/internal IP from config
    vps = "100.103.119.5"
    container = config['openclaw']['container_name']
    
    print(f"--- Starting Advanced OpenClaw Security Audit on {vps} ---")
    
    # 1. Host Hardening
    print("\n[1] Checking Host Hardening...")
    stdout, _, _ = run_ssh(vps, "sshd -T | grep -E 'port|passwordauthentication|allowusers'")
    print(f"SSH Config:\n{stdout.strip()}")
    
    stdout, _, _ = run_ssh(vps, "sudo -l -U ubuntu")
    if "not allowed" in stdout or "not present" in stdout:
        print("✅ Ubuntu user: Locked/No Sudo")
    else:
        print("❌ Ubuntu user: STILL HAS SUDO ACCESS")

    # 2. Firewall & Docker
    print("\n[2] Checking Firewall & Docker Isolation...")
    stdout, _, _ = run_ssh(vps, "iptables -L DOCKER-USER -n")
    if "DROP" in stdout and "LOG" in stdout:
        print("✅ DOCKER-USER: Isolation & Logging active")
    else:
        print("❌ DOCKER-USER: Rules MISSING")
        
    stdout, _, _ = run_ssh(vps, f"docker inspect {container} --format '{{{{.HostConfig.PidsLimit}}}}' && docker inspect {container} --format '{{{{.State.Privileged}}}}'")
    print(f"Docker (PidsLimit / Privileged): {stdout.strip()}")

    # 3. Backup & Secrets
    print("\n[3] Checking Backup & Secret Security...")
    stdout, _, _ = run_ssh(vps, "grep 'gpg' /root/backup_openclaw.sh && ls -la /root/.backup_passphrase")
    if "/root/.backup_passphrase" in stdout:
        print("✅ Backup: Encryption & Passphrase file found")
    else:
        print("❌ Backup: Encryption NOT configured")
        
    stdout, _, _ = run_ssh(vps, "rclone listremotes")
    if "b2-backup:" in stdout:
        print("✅ Offsite: rclone b2-backup configured")
    else:
        print("❌ Offsite: rclone NOT configured")

    # 4. Nginx Security Headers
    print("\n[4] Checking Nginx Security Headers (oc.andriko.xyz)...")
    stdout, _, _ = run_ssh(vps, "curl -I -s https://oc.andriko.xyz")
    headers = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"]
    for h in headers:
        if h in stdout:
            print(f"✅ {h}: Found")
        else:
            print(f"❌ {h}: MISSING")

    # 5. Internal OpenClaw Audit
    print("\n[5] Running internal OpenClaw audit...")
    stdout, stderr, code = run_ssh(vps, f"docker exec {container} openclaw security audit")
    print(stdout if stdout else stderr)

    print("\n--- Advanced Audit Complete ---")

if __name__ == "__main__":
    main()
