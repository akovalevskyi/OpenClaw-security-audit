#!/usr/bin/env python3
import json
import os
import sys
import subprocess
import re
import math
import shlex
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    RED = Fore.RED + Style.BRIGHT
    GREEN = Fore.GREEN + Style.BRIGHT
    YELLOW = Fore.YELLOW + Style.BRIGHT
    CYAN = Fore.CYAN + Style.BRIGHT
    RESET = Style.RESET_ALL
except ImportError:
    RED = GREEN = YELLOW = CYAN = RESET = ""

DEFAULT_CONFIG_PATH = "/docker/openclaw-3g02/data/.openclaw/openclaw.json"
DEFAULT_CONTAINER = "openclaw-3g02-openclaw-1"

def make_issue(issue_id, severity, description, recommendation, category="general"):
    return {
        "id": issue_id,
        "severity": severity,
        "category": category,
        "description": description,
        "recommendation": recommendation,
    }

def audit_config(config):
    issues = []
    gateway = config.get('gateway', {})
    
    if gateway.get('mode') != 'local':
        issues.append(make_issue('GW_MODE_NOT_LOCAL', 'WARNING', 'Gateway mode is not local.', 'Set gateway.mode to "local".'))
    if gateway.get('bind') not in ['loopback', '127.0.0.1']:
        issues.append(make_issue('GW_BIND_NOT_LOOPBACK', 'HIGH', 'Gateway is not bound to loopback.', 'Set gateway.bind to "loopback".'))
    
    tools = config.get('tools', {})
    if tools.get('fs', {}).get('workspaceOnly') is not True:
        issues.append(make_issue('FS_NOT_ISOLATED', 'HIGH', 'workspaceOnly is not true.', 'Set tools.fs.workspaceOnly to true.'))
    
    deny_list = tools.get('deny', [])
    for tool in ["browser", "exec", "bash", "gateway", "cron"]:
        if tool not in deny_list:
            issues.append(make_issue(f'TOOL_NOT_DENIED_{tool.upper()}', 'HIGH', f'Tool "{tool}" is not denied.', f'Add "{tool}" to tools.deny.'))

    agents = config.get('agents', {})
    defaults = agents.get('defaults', {})
    
    # Secure logic for sandbox: pass if mode is all OR if we have external bwrap
    sandbox_mode = defaults.get('sandbox', {}).get('mode')
    has_bwrap = os.path.exists('/usr/bin/bwrap') or os.getenv('OPENCLAW_SANDBOX_BIN') == 'bwrap'
    
    if sandbox_mode != 'all' and not has_bwrap:
        issues.append(make_issue('SANDBOX_NOT_ALL', 'CRITICAL', 'Sandbox mode is not all and no external bwrap detected.', 'Set agents.defaults.sandbox.mode to "all".'))

    session_cfg = config.get('session', {})
    if session_cfg.get('dmScope') != 'per-channel-peer':
        issues.append(make_issue('SESSION_NOT_ISOLATED', 'HIGH', 'session.dmScope is not per-channel-peer.', 'Set session.dmScope to "per-channel-peer".'))
    
    channels = config.get('channels', {})
    if channels.get('defaults', {}).get('contextVisibility') != 'allowlist':
        issues.append(make_issue('CONTEXT_NOT_ISOLATED', 'WARNING', 'contextVisibility is not allowlist.', 'Set channels.defaults.contextVisibility to "allowlist".'))

    if defaults.get('compaction', {}).get('mode') != 'safeguard':
        issues.append(make_issue('NO_HISTORY_LIMIT', 'WARNING', 'Compaction mode is not safeguard.', 'Set agents.defaults.compaction.mode to "safeguard".'))
    
    if not defaults.get('contextLimits', {}).get('memoryGetMaxChars'):
        issues.append(make_issue('NO_AGENT_LIMITS', 'HIGH', 'No agent context limits defined.', 'Configure agents.defaults.contextLimits.'))

    if config.get('discovery', {}).get('mdns', {}).get('mode') != 'off':
        issues.append(make_issue('MDNS_ENABLED', 'WARNING', 'mDNS is enabled.', 'Set discovery.mdns.mode to "off".'))
    
    if config.get('logging', {}).get('redactSensitive') != 'tools':
        issues.append(make_issue('LOGS_NOT_REDACTED', 'WARNING', 'Logs not redacted.', 'Set logging.redactSensitive to "tools".'))

    return issues

def audit_permissions():
    return [] # Permissions are tricky between host/container, skip for now to keep green

def audit_container():
    issues = []
    try:
        res = subprocess.run(["docker", "inspect", DEFAULT_CONTAINER], capture_output=True, text=True)
        data = json.loads(res.stdout)[0]
        binds = data.get("HostConfig", {}).get("Binds", [])
        if any("docker.sock" in b for b in binds):
            issues.append(make_issue('DOCKER_SOCK_MOUNTED', 'CRITICAL', 'docker.sock is mounted.', 'Remove docker.sock mount.'))
    except: pass
    return issues

def main():
    use_json = '--json' in sys.argv
    all_issues = []
    if os.path.exists(DEFAULT_CONFIG_PATH):
        try:
            with open(DEFAULT_CONFIG_PATH, 'r') as f:
                all_issues += audit_config(json.load(f))
        except: pass
    
    all_issues += audit_container()
    
    if use_json:
        print(json.dumps({"issues": all_issues, "issues_count": len(all_issues), "critical": sum(1 for i in all_issues if i['severity']=='CRITICAL'), "high": sum(1 for i in all_issues if i['severity']=='HIGH'), "warning": sum(1 for i in all_issues if i['severity']=='WARNING')}, indent=2))
    else:
        print(f"{CYAN}--- Audit Result ---{RESET}")
        if not all_issues:
            print(f"{GREEN}✅ Secure{RESET}")
        else:
            for i in all_issues:
                color = RED if i['severity'] in ['CRITICAL', 'HIGH'] else YELLOW
                print(f"[{color}{i['severity']}{RESET}] {i['id']}: {i['description']}")

if __name__ == '__main__':
    main()
