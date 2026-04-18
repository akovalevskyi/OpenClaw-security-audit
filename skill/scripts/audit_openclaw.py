import json
import subprocess
import sys
import os

def run_ssh(host, command):
    full_cmd = f"ssh {host} \"{command}\""
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
    
    vps = config['openclaw']['vps_host']
    container = config['openclaw']['container_name']
    
    print(f"--- Starting OpenClaw Security Audit on {vps} ---")
    
    # 1. Internal Audit
    print("\n[1] Running internal OpenClaw audit...")
    stdout, stderr, code = run_ssh(vps, f"docker exec {container} openclaw security audit")
    print(stdout if stdout else stderr)
    
    # 2. Check Nginx Security Headers
    print("\n[2] Checking Nginx Security Headers (oc.andriko.xyz)...")
    stdout, stderr, code = run_ssh(vps, "curl -I -s https://oc.andriko.xyz")
    headers = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"]
    for h in headers:
        if h in stdout:
            print(f"✅ {h}: Found")
        else:
            print(f"❌ {h}: MISSING")
            
    # 3. Check Docker-User Firewall
    print("\n[3] Checking DOCKER-USER Firewall Chain...")
    stdout, stderr, code = run_ssh(vps, "iptables -L DOCKER-USER -n")
    if "DROP" in stdout and "eth0" in stdout:
        print("✅ DOCKER-USER: eth0 isolation active")
    else:
        print("❌ DOCKER-USER: Isolation MISSING or incomplete")

    # 4. Check File Permissions
    print("\n[4] Checking File Permissions...")
    stdout, stderr, code = run_ssh(vps, f"ls -ld /docker/openclaw-3g02/data/.openclaw && ls -l /docker/openclaw-3g02/data/.openclaw/openclaw.json")
    print(stdout)

    print("\n--- Audit Complete ---")

if __name__ == "__main__":
    main()
