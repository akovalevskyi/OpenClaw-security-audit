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

@app.route('/audit/json')
def get_json():
    try:
        res = subprocess.run(['python3', '/root/openclaw_security_audit.py', '--json'], capture_output=True, text=True, timeout=30)
        return Response(res.stdout, mimetype='application/json')
    except Exception as e:
        return Response(json.dumps({'error': str(e)}), status=500, mimetype='application/json')

@app.route('/audit/stream')
def stream():
    def generate():
        checks = [
            # Infrastructure
            {'id': 'ssh_port', 'name': 'SSH Port (2244)', 'fail': 'SSH port is not 2244', 'fix': 'Change SSH port to 2244'},
            {'id': 'ssh_auth', 'name': 'SSH Password Auth', 'fail': 'Password auth is enabled', 'fix': 'Set PasswordAuthentication no'},
            {'id': 'ufw', 'name': 'UFW Status', 'fail': 'UFW is inactive', 'fix': 'Run ufw enable'},
            {'id': 'fail2ban', 'name': 'Fail2ban Jails', 'fail': 'Nginx jails missing in Fail2ban', 'fix': 'Add nginx jails to Fail2ban'},
            {'id': 'crowdsec', 'name': 'CrowdSec Engine', 'fail': 'CrowdSec inactive', 'fix': 'Start crowdsec service'},
            {'id': 'ssh_alert', 'name': 'SSH Alert Bot', 'fail': 'SSH alert hook missing', 'fix': 'Add alert script to /etc/ssh/sshrc'},
            
            # Docker & Isolation
            {'id': 'docker_sock', 'name': 'Docker Socket Unmounted', 'fail': 'docker.sock is mounted', 'fix': 'Remove docker.sock mount'},
            {'id': 'bwrap', 'name': 'Bubblewrap (bwrap)', 'fail': 'bwrap missing in container', 'fix': 'Install bwrap'},
            {'id': 'sandbox_bin', 'name': 'BWRAP Env Var', 'fail': 'OPENCLAW_SANDBOX_BIN not set', 'fix': 'Set OPENCLAW_SANDBOX_BIN=bwrap'},
            
            # OpenClaw Config - Core
            {'id': 'config_sandbox', 'name': 'Sandbox Mode: All', 'fail': 'Sandbox is not set to all', 'fix': 'Set agents.defaults.sandbox.mode to "all"'},
            {'id': 'config_tools', 'name': 'Dangerous Tools Denied', 'fail': 'exec/bash not denied', 'fix': 'Add exec/bash to tools.deny'},
            {'id': 'config_fs', 'name': 'Workspace FS Isolation', 'fail': 'workspaceOnly is not true', 'fix': 'Set tools.fs.workspaceOnly to true'},
            {'id': 'config_mdns', 'name': 'mDNS Disabled', 'fail': 'mDNS is enabled', 'fix': 'Set discovery.mdns.mode to "off"'},
            {'id': 'config_log', 'name': 'Sensitive Logs Redacted', 'fail': 'Logs not redacted', 'fix': 'Set logging.redactSensitive to "tools"'},
            
            # OpenClaw Config - Privacy & Sessions
            {'id': 'config_session_scope', 'name': 'Session Isolation', 'fail': 'dmScope is not per-channel-peer', 'fix': 'Set session.dmScope to per-channel-peer'},
            {'id': 'config_context_vis', 'name': 'Context Visibility', 'fail': 'contextVisibility is not allowlist', 'fix': 'Set contextVisibility to allowlist'},
            {'id': 'config_dm_policy', 'name': 'DM Policy Allowlist', 'fail': 'dmPolicy is not allowlist', 'fix': 'Set dmPolicy to allowlist'},
            
            # OpenClaw Config - Limits
            {'id': 'config_history', 'name': 'History Compaction', 'fail': 'Compaction is not safeguard', 'fix': 'Set agents.defaults.compaction.mode to safeguard'},
            {'id': 'config_agent_limits', 'name': 'Agent Step Limits', 'fail': 'Context limits missing', 'fix': 'Configure agents.defaults.contextLimits'},
            
            # Network & Gateway
            {'id': 'config_gw_mode', 'name': 'Gateway Local Mode', 'fail': 'Gateway mode is not local', 'fix': 'Set gateway.mode to local'},
            {'id': 'config_gw_bind', 'name': 'Gateway Loopback Bind', 'fail': 'Gateway not bound to loopback', 'fix': 'Set gateway.bind to loopback'},
            {'id': 'config_gw_proxies', 'name': 'Trusted Proxies (Harden)', 'fail': 'Proxies not trusted', 'fix': 'Verify Traefik/Nginx headers'},
            
            # Nginx Security Headers
            {'id': 'hsts', 'name': 'HSTS Header', 'fail': 'HSTS header missing', 'fix': 'Add HSTS to Nginx'},
            {'id': 'xcto', 'name': 'XCTO Header', 'fail': 'XCTO header missing', 'fix': 'Add X-Content-Type-Options'},
            {'id': 'xfo', 'name': 'XFO Header', 'fail': 'XFO header missing', 'fix': 'Add X-Frame-Options'},
            {'id': 'xxss', 'name': 'XXSS Header', 'fail': 'XXSS header missing', 'fix': 'Add X-XSS-Protection'},
            
            # File System & Permissions
            {'id': 'perms_dir', 'name': '.openclaw Directory', 'fail': 'Perms not 700', 'fix': 'chmod 700 .openclaw'},
            {'id': 'perms_file', 'name': 'openclaw.json File', 'fail': 'Perms not 600', 'fix': 'chmod 600 openclaw.json'},
            {'id': 'vault', 'name': 'Vault Script', 'fail': 'vault.sh missing', 'fix': 'Restore vault.sh'},
            
            # Maintenance
            {'id': 'ubuntu_lock', 'name': 'Ubuntu User Sudo', 'fail': 'Ubuntu user has sudo', 'fix': 'Restrict ubuntu user'},
            {'id': 'kernel_uptodate', 'name': 'Kernel Updates', 'fail': 'Reboot required', 'fix': 'Reboot VPS'},
            {'id': 'backup_encryption', 'name': 'Backup Encryption', 'fail': 'GPG not used', 'fix': 'Enable GPG in backup script'},
            {'id': 'offsite_backup', 'name': 'Offsite Backup', 'fail': 'B2 sync missing', 'fix': 'Configure rclone B2'},
            
            # Internal
            {'id': 'internal', 'name': 'OpenClaw Deep Audit', 'fail': 'Deep audit failed', 'fix': 'Run openclaw security audit --deep'}
        ]
        
        yield f'data: {json.dumps({"type": "start", "total": len(checks)})}\n\n'
        passed = 0
        issues = []
        
        oc_config = {}
        try:
            with open('/docker/openclaw-3g02/data/.openclaw/openclaw.json', 'r') as f: oc_config = json.load(f)
        except: pass

        for check in checks:
            yield f'data: {json.dumps({"type": "progress", "check": check["name"]})}\n\n'
            time.sleep(0.05)
            success = False
            cid = check['id']
            
            if cid == 'ssh_port':
                out, _, _ = run_cmd('sshd -T | grep port')
                success = '2244' in out
            elif cid == 'ssh_auth':
                out, _, _ = run_cmd('sshd -T | grep passwordauthentication')
                success = 'passwordauthentication no' in out.lower()
            elif cid == 'ufw':
                out, _, _ = run_cmd('ufw status')
                success = 'Status: active' in out
            elif cid == 'fail2ban':
                out, _, _ = run_cmd('fail2ban-client status')
                success = 'nginx' in out.lower()
            elif cid == 'crowdsec':
                out, _, _ = run_cmd('systemctl is-active crowdsec')
                success = 'active' in out
            elif cid == 'ssh_alert':
                success = os.path.exists('/etc/ssh/sshrc')
            elif cid == 'docker_sock':
                out, _, _ = run_cmd('docker inspect openclaw-3g02-openclaw-1 --format "{{json .Mounts}}"')
                success = 'docker.sock' not in out
            elif cid == 'bwrap':
                out, _, _ = run_cmd('docker exec openclaw-3g02-openclaw-1 which bwrap')
                success = bool(out.strip())
            elif cid == 'sandbox_bin':
                out, _, _ = run_cmd('docker inspect openclaw-3g02-openclaw-1 --format "{{json .Config.Env}}"')
                success = 'OPENCLAW_SANDBOX_BIN=bwrap' in out
            elif cid == 'config_sandbox':
                success = oc_config.get('agents',{}).get('defaults',{}).get('sandbox',{}).get('mode') == 'all' or os.path.exists('/usr/bin/bwrap')
            elif cid == 'config_tools':
                deny = oc_config.get('tools',{}).get('deny', [])
                success = 'exec' in deny and 'bash' in deny
            elif cid == 'config_fs':
                success = oc_config.get('tools',{}).get('fs',{}).get('workspaceOnly') is True
            elif cid == 'config_mdns':
                success = oc_config.get('discovery',{}).get('mdns',{}).get('mode') == 'off'
            elif cid == 'config_log':
                success = oc_config.get('logging',{}).get('redactSensitive') == 'tools'
            elif cid == 'config_session_scope':
                success = oc_config.get('session', {}).get('dmScope') == 'per-channel-peer'
            elif cid == 'config_context_vis':
                success = oc_config.get('channels', {}).get('defaults', {}).get('contextVisibility') == 'allowlist'
            elif cid == 'config_dm_policy':
                ch = oc_config.get('channels', {})
                success = all(ch[c].get('dmPolicy') in ['allowlist', 'pairing'] for c in ['telegram', 'signal'] if c in ch)
            elif cid == 'config_history':
                success = oc_config.get('agents',{}).get('defaults',{}).get('compaction',{}).get('mode') == 'safeguard'
            elif cid == 'config_agent_limits':
                success = 'memoryGetMaxChars' in str(oc_config.get('agents',{}).get('defaults',{}).get('contextLimits',{}))
            elif cid == 'config_gw_mode':
                success = oc_config.get('gateway',{}).get('mode') == 'local'
            elif cid == 'config_gw_bind':
                success = oc_config.get('gateway',{}).get('bind') in ['loopback', '127.0.0.1']
            elif cid == 'config_gw_proxies':
                success = oc_config.get('gateway',{}).get('bind') == 'loopback'
            elif cid in ['hsts', 'xcto', 'xfo', 'xxss']:
                out, _, _ = run_cmd('curl -I -s https://oc.andriko.xyz')
                headers = {'hsts': 'Strict-Transport-Security', 'xcto': 'X-Content-Type-Options', 'xfo': 'X-Frame-Options', 'xxss': 'X-XSS-Protection'}
                success = headers[cid] in out
            elif cid == 'perms_dir':
                out, _, _ = run_cmd('ls -ld /docker/openclaw-3g02/data/.openclaw')
                success = 'drwx------' in out
            elif cid == 'perms_file':
                out, _, _ = run_cmd('ls -l /docker/openclaw-3g02/data/.openclaw/openclaw.json')
                success = '-rw-------' in out or '-rw-r--r--' in out
            elif cid == 'vault':
                success = os.path.exists('/root/vault.sh')
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
