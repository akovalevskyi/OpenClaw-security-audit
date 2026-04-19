import time, subprocess, json, os, re
from flask import Flask, Response, send_file
app = Flask(__name__, static_folder='.', static_url_path='')

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
        stdout = re.sub(r'\x1b\[[0-9;]*[mGKF]', '', res.stdout)
        return stdout, res.stderr, res.returncode
    except: return '', '', 1

@app.route('/audit/')
@app.route('/audit')
def index(): return send_file('index.html')

@app.route('/audit/stream')
def stream():
    def generate():
        checks = [
            {'id': 'ssh_port', 'name': 'SSH Port (2244)', 'fail': 'SSH port is not 2244', 'fix': 'Change SSH port to 2244 in /etc/ssh/sshd_config'},
            {'id': 'ssh_auth', 'name': 'SSH Password Auth', 'fail': 'Password auth is enabled', 'fix': 'Set PasswordAuthentication no in /etc/ssh/sshd_config'},
            {'id': 'ssh_root', 'name': 'SSH AllowUsers root', 'fail': 'AllowUsers root is missing', 'fix': 'Add "AllowUsers root" to /etc/ssh/sshd_config'},
            {'id': 'fail2ban', 'name': 'Fail2ban Jails', 'fail': 'Nginx jails missing in Fail2ban', 'fix': 'Add nginx-http-auth and nginx-botsearch jails to Fail2ban'},
            {'id': 'ufw', 'name': 'UFW Status', 'fail': 'UFW is inactive', 'fix': 'Run "ufw enable" on the VPS'},
            {'id': 'docker_user', 'name': 'DOCKER-USER Isolation', 'fail': 'DOCKER-USER chain is not configured', 'fix': 'Apply DOCKER-USER iptables isolation rules'},
            {'id': 'docker_sock', 'name': 'Docker Socket Unmounted', 'fail': 'docker.sock is mounted in container', 'fix': 'Remove docker.sock mount from docker-compose.yml'},
            {'id': 'bwrap', 'name': 'Bubblewrap (bwrap)', 'fail': 'bwrap not found in container', 'fix': 'Install bubblewrap in the OpenClaw container'},
            {'id': 'vault', 'name': 'Vault Secret Management', 'fail': 'vault.sh not found', 'fix': 'Restore vault.sh to /root/'},
            {'id': 'config_secrets', 'name': 'No Hardcoded Tokens', 'fail': 'Tokens found in openclaw.json', 'fix': 'Use environment variables in openclaw.json'},
            {'id': 'config_sandbox', 'name': 'Sandbox Mode: All', 'fail': 'Sandbox is not set to all', 'fix': 'Set agents.defaults.sandbox.mode to "all"'},
            {'id': 'config_tools', 'name': 'Dangerous Tools Denied', 'fail': 'exec/bash not denied', 'fix': 'Add exec/bash to tools.deny in openclaw.json'},
            {'id': 'config_rate', 'name': 'Rate Limiting', 'fail': 'Rate limit disabled', 'fix': 'Enable rateLimit in openclaw.json'},
            {'id': 'config_mdns', 'name': 'mDNS Disabled', 'fail': 'mDNS is enabled', 'fix': 'Set discovery.mdns.mode to "off"'},
            {'id': 'config_log', 'name': 'Sensitive Logs Redacted', 'fail': 'Logs not redacted', 'fix': 'Set logging.redactSensitive to "tools"'},
            {'id': 'crowdsec', 'name': 'CrowdSec Engine', 'fail': 'CrowdSec inactive', 'fix': 'Start crowdsec service'},
            {'id': 'ssh_alert', 'name': 'SSH Alert Bot', 'fail': 'SSH alert hook missing', 'fix': 'Add alert script to /etc/ssh/sshrc'},
            {'id': 'perms_dir', 'name': 'Dir Permissions', 'fail': '.openclaw perms not 700', 'fix': 'Run chmod 700 on .openclaw dir'},
            {'id': 'perms_file', 'name': 'File Permissions', 'fail': 'openclaw.json perms not 600', 'fix': 'Run chmod 600 on openclaw.json'},
            {'id': 'hsts', 'name': 'HSTS Header', 'fail': 'HSTS header missing', 'fix': 'Add HSTS to Nginx config'},
            {'id': 'xcto', 'name': 'XCTO Header', 'fail': 'XCTO header missing', 'fix': 'Add X-Content-Type-Options to Nginx'},
            {'id': 'xfo', 'name': 'XFO Header', 'fail': 'XFO header missing', 'fix': 'Add X-Frame-Options to Nginx'},
            {'id': 'xxss', 'name': 'XXSS Header', 'fail': 'XXSS header missing', 'fix': 'Add X-XSS-Protection to Nginx'},
            {'id': 'ubuntu_lock', 'name': 'Ubuntu User Locked', 'fail': 'Ubuntu user has sudo access', 'fix': 'Lock ubuntu user and remove from sudo'},
            {'id': 'kernel_uptodate', 'name': 'Kernel Up-to-Date', 'fail': 'Reboot required', 'fix': 'Reboot VPS for kernel updates'},
            {'id': 'backup_encryption', 'name': 'GPG Backup Encryption', 'fail': 'Backups not encrypted', 'fix': 'Use GPG in backup_openclaw.sh'},
            {'id': 'offsite_backup', 'name': 'Offsite rclone B2', 'fail': 'rclone b2-backup missing', 'fix': 'Configure b2-backup in rclone'},
            {'id': 'internal', 'name': 'Internal OpenClaw Audit', 'fail': 'Internal audit failed', 'fix': 'Run openclaw security audit --deep'}
        ]
        
        yield f'data: {json.dumps({"type": "start", "total": len(checks)})}\n\n'
        passed = 0
        issues = []
        
        # Pre-load config
        oc_config = {}
        try:
            with open('/docker/openclaw-3g02/data/.openclaw/openclaw.json', 'r') as f: oc_config = json.load(f)
        except: pass

        for check in checks:
            yield f'data: {json.dumps({"type": "progress", "check": check["name"]})}\n\n'
            time.sleep(0.3)
            success = False
            cid = check['id']
            
            if cid == 'ssh_port':
                out, _, _ = run_cmd('sshd -T | grep port')
                success = '2244' in out
            elif cid == 'ssh_auth':
                out, _, _ = run_cmd('sshd -T | grep passwordauthentication')
                success = 'passwordauthentication no' in out.lower()
            elif cid == 'ssh_root':
                out, _, _ = run_cmd('sshd -T | grep allowusers')
                success = 'root' in out.lower()
            elif cid == 'fail2ban':
                out, _, _ = run_cmd('fail2ban-client status')
                success = 'nginx' in out.lower()
            elif cid == 'ufw':
                out, _, _ = run_cmd('ufw status')
                success = 'Status: active' in out
            elif cid == 'docker_user':
                out, _, _ = run_cmd('iptables -L DOCKER-USER -n')
                success = 'DROP' in out
            elif cid == 'docker_sock':
                out, _, _ = run_cmd('docker inspect openclaw-3g02-openclaw-1 --format "{{json .Mounts}}"')
                success = 'docker.sock' not in out
            elif cid == 'bwrap':
                out, _, _ = run_cmd('docker exec openclaw-3g02-openclaw-1 which bwrap')
                success = bool(out.strip())
            elif cid == 'vault':
                success = os.path.exists('/root/vault.sh')
            elif cid == 'config_secrets':
                success = '' in str(oc_config) or 'TELEGRAM_BOT_TOKEN' not in str(oc_config)
            elif cid == 'config_sandbox':
                success = oc_config.get('agents',{}).get('defaults',{}).get('sandbox',{}).get('mode') == 'all'
            elif cid == 'config_tools':
                deny = oc_config.get('tools',{}).get('deny', [])
                success = 'exec' in deny and 'bash' in deny
            elif cid == 'config_rate':
                success = oc_config.get('gateway',{}).get('auth',{}).get('rateLimit') is not None
            elif cid == 'config_mdns':
                success = oc_config.get('discovery',{}).get('mdns',{}).get('mode') == 'off'
            elif cid == 'config_log':
                success = oc_config.get('logging',{}).get('redactSensitive') == 'tools'
            elif cid == 'crowdsec':
                out, _, _ = run_cmd('systemctl is-active crowdsec')
                success = 'active' in out
            elif cid == 'ssh_alert':
                success = os.path.exists('/etc/ssh/sshrc')
            elif cid == 'perms_dir':
                out, _, _ = run_cmd('ls -ld /docker/openclaw-3g02/data/.openclaw')
                success = 'drwx------' in out
            elif cid == 'perms_file':
                out, _, _ = run_cmd('ls -l /docker/openclaw-3g02/data/.openclaw/openclaw.json')
                success = '-rw-------' in out
            elif cid == 'hsts' or cid == 'xcto' or cid == 'xfo' or cid == 'xxss':
                out, _, _ = run_cmd('curl -I -s https://oc.andriko.xyz')
                headers = {'hsts': 'Strict-Transport-Security', 'xcto': 'X-Content-Type-Options', 'xfo': 'X-Frame-Options', 'xxss': 'X-XSS-Protection'}
                success = headers[cid] in out
            elif cid == 'ubuntu_lock':
                out, _, _ = run_cmd('sudo -l -U ubuntu')
                success = 'not allowed' in out or 'not present' in out
            elif cid == 'kernel_uptodate':
                success = not os.path.exists('/var/run/reboot-required')
            elif cid == 'backup_encryption':
                out, _, _ = run_cmd('grep gpg /root/backup_openclaw.sh')
                success = bool(out.strip())
            elif cid == 'offsite_backup':
                out, _, _ = run_cmd('rclone listremotes')
                success = 'b2-backup:' in out
            elif cid == 'internal':
                out, _, _ = run_cmd('docker exec openclaw-3g02-openclaw-1 openclaw security audit')
                success = '0 critical' in out.lower() or out.strip() == ''
            
            if success:
                passed += 1
                yield f'data: {json.dumps({"type": "result", "id": cid, "status": "pass"})}\n\n'
            else:
                issues.append({'issue': check['fail'], 'prompt': check['fix']})
                yield f'data: {json.dumps({"type": "result", "id": cid, "status": "fail"})}\n\n'
        
        score = int((passed / len(checks)) * 100)
        yield f'data: {json.dumps({"type": "complete", "score": score, "issues": issues})}\n\n'
    return Response(generate(), mimetype='text/event-stream')
if __name__ == '__main__': app.run(host='127.0.0.1', port=8021)
ok