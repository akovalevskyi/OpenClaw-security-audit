#!/usr/bin/env python3
"""
OpenClaw Security Audit Tool
A standalone CLI and Web Dashboard utility for auditing OpenClaw VPS installations.

Usage:
  python3 openclaw_audit.py          # Runs the audit in CLI mode
  python3 openclaw_audit.py --web    # Starts the Web Dashboard on port 8021
"""

import time
import subprocess
import json
import os
import sys
import argparse

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenClaw Security Audit</title>
    <style>
        :root {
            --bg-color: #121212;
            --text-color: #ffffff;
            --accent-color: #bb86fc;
            --success-color: #03dac6;
            --error-color: #cf6679;
            --card-bg: #1e1e1e;
            --pulse-color: #bb86fc;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 40px 20px;
            box-sizing: border-box;
        }
        h1 {
            font-weight: 300;
            margin-bottom: 40px;
            text-align: center;
        }
        .container {
            background-color: var(--card-bg);
            border-radius: 16px;
            padding: 40px;
            width: 100%;
            max-width: 600px;
            display: flex;
            flex-direction: column;
            align-items: center;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
            position: relative;
        }
        
        /* SVG Circular Progress Bar */
        .circle-wrap {
            position: relative;
            width: 240px;
            height: 240px;
            margin-bottom: 30px;
            display: flex;
            justify-content: center;
            align-items: center;
            border-radius: 50%;
        }
        /* Hardware accelerated glow pulse */
        .circle-wrap::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            border-radius: 50%;
            box-shadow: 0 0 25px var(--pulse-color);
            opacity: 0;
            z-index: 1;
            pointer-events: none;
        }
        .pulsing-circle::before {
            animation: pulse-glow 2s infinite ease-in-out;
        }
        @keyframes pulse-glow {
            0% { opacity: 0; transform: scale(1); }
            50% { opacity: 1; transform: scale(1.05); }
            100% { opacity: 0; transform: scale(1); }
        }

        svg {
            transform: rotate(-90deg);
            width: 100%;
            height: 100%;
            z-index: 2;
        }
        .circle-bg {
            fill: none;
            stroke: #2a2a2a;
            stroke-width: 12;
        }
        .circle-progress {
            fill: none;
            stroke: var(--accent-color);
            stroke-width: 12;
            stroke-linecap: butt;
            stroke-dasharray: 691.15;
            stroke-dashoffset: 691.15;
            transition: stroke-dashoffset 0.6s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.5s ease;
        }
        .inside-circle {
            position: absolute;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            z-index: 10;
        }
        #score-text {
            font-size: 4em;
            font-weight: bold;
            transition: color 0.5s;
            line-height: 1;
        }
        
        #status-text {
            font-size: 1.2em;
            margin-bottom: 20px;
            text-align: center;
            min-height: 30px;
            color: #aaa;
        }
        
        button {
            background-color: var(--accent-color);
            color: #000;
            border: none;
            padding: 14px 36px;
            font-size: 1.1em;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
            margin-bottom: 30px;
            z-index: 10;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(187, 134, 252, 0.4);
        }
        button:disabled {
            background-color: #555;
            color: #888;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        /* Clean Checklist */
        #checklist-container {
            width: 100%;
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-bottom: 20px;
        }
        .check-item {
            display: flex;
            align-items: center;
            background: #252525;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 0.95em;
            opacity: 0;
            transform: translateY(10px);
            animation: slideIn 0.3s forwards;
        }
        @keyframes slideIn {
            to { opacity: 1; transform: translateY(0); }
        }
        .check-icon {
            margin-right: 12px;
            font-size: 1.2em;
            width: 24px;
            text-align: center;
        }
        .check-icon.loading {
            animation: spin 1s linear infinite;
            color: var(--accent-color);
        }
        @keyframes spin {
            100% { transform: rotate(360deg); }
        }
        .check-text {
            flex-grow: 1;
            color: #ddd;
        }

        .issues-container {
            width: 100%;
            margin-top: 30px;
            display: none;
            border-top: 1px solid #333;
            padding-top: 20px;
        }
        .issue-card {
            background-color: #2a2a2a;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid var(--error-color);
        }
        .issue-title {
            color: var(--error-color);
            font-weight: bold;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        .prompt-box {
            background-color: #121212;
            padding: 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
            margin-bottom: 10px;
            color: #ddd;
            word-wrap: break-word;
        }
        .copy-btn {
            background-color: #333;
            color: #fff;
            border: 1px solid #444;
            padding: 8px 16px;
            font-size: 0.9em;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .copy-btn:hover {
            background-color: #444;
        }
    </style>
</head>
<body>

    <h1>OpenClaw Security Audit</h1>

    <div class="container">
        <div class="circle-wrap" id="circle-wrap">
            <svg>
                <circle class="circle-bg" cx="120" cy="120" r="110"></circle>
                <circle class="circle-progress" id="progress-circle" cx="120" cy="120" r="110"></circle>
            </svg>
            <div class="inside-circle">
                <div id="score-text">0</div>
            </div>
        </div>

        <div id="status-text">Ready to start audit</div>
        
        <button id="start-btn" onclick="startAudit()">Run Security Audit</button>

        <div id="checklist-container"></div>

        <div class="issues-container" id="issues-container">
            <h2 style="margin-top: 0; color: var(--error-color);">Issues Found</h2>
            <div id="issues-list"></div>
        </div>
    </div>

    <script>
        const circumference = 691.15;

        function setProgress(percent) {
            const circle = document.getElementById('progress-circle');
            const offset = circumference - (percent / 100) * circumference;
            circle.style.strokeDashoffset = offset;
        }

        let currentDisplayedScore = 0;
        let animationFrameId = null;

        function animateScoreTo(targetScore) {
            if (animationFrameId) cancelAnimationFrame(animationFrameId);
            const scoreElement = document.getElementById('score-text');
            
            function update() {
                if (currentDisplayedScore < targetScore) {
                    currentDisplayedScore++;
                    scoreElement.innerText = currentDisplayedScore;
                    animationFrameId = requestAnimationFrame(update);
                } else if (currentDisplayedScore > targetScore) {
                    currentDisplayedScore--;
                    scoreElement.innerText = currentDisplayedScore;
                    animationFrameId = requestAnimationFrame(update);
                }
            }
            animationFrameId = requestAnimationFrame(update);
        }

        function getColorForScore(score) {
            if (score <= 50) return '#cf6679'; // Red
            if (score <= 75) return '#ffb74d'; // Orange
            if (score <= 89) return '#fff59d'; // Yellow
            return '#03dac6'; // Green
        }

        function setFillColor(color) {
            document.getElementById('progress-circle').style.stroke = color;
            document.documentElement.style.setProperty('--pulse-color', color);
            document.getElementById('score-text').style.color = color;
        }

        function copyToClipboard(text, btn) {
            navigator.clipboard.writeText(text).then(() => {
                const oldText = btn.innerText;
                btn.innerText = 'Copied!';
                btn.style.backgroundColor = 'var(--success-color)';
                btn.style.color = '#000';
                setTimeout(() => { 
                    btn.innerText = oldText; 
                    btn.style.backgroundColor = '#333';
                    btn.style.color = '#fff';
                }, 2000);
            });
        }
        
        let currentCheckElement = null;

        function addChecklistItem(text) {
            const container = document.getElementById('checklist-container');
            const item = document.createElement('div');
            item.className = 'check-item';
            
            const icon = document.createElement('div');
            icon.className = 'check-icon loading';
            icon.innerHTML = '⟳';
            
            const textDiv = document.createElement('div');
            textDiv.className = 'check-text';
            textDiv.innerText = text;
            
            item.appendChild(icon);
            item.appendChild(textDiv);
            container.appendChild(item);
            
            currentCheckElement = icon;
            window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
        }
        
        function updateCurrentChecklist(status) {
            if (!currentCheckElement) return;
            currentCheckElement.classList.remove('loading');
            
            if (status === 'pass') {
                currentCheckElement.innerHTML = '✅';
                currentCheckElement.style.color = 'var(--success-color)';
            } else {
                currentCheckElement.innerHTML = '❌';
                currentCheckElement.style.color = 'var(--error-color)';
            }
        }

        function startAudit() {
            const btn = document.getElementById('start-btn');
            const statusText = document.getElementById('status-text');
            const scoreText = document.getElementById('score-text');
            const issuesContainer = document.getElementById('issues-container');
            const issuesList = document.getElementById('issues-list');
            const circleWrap = document.getElementById('circle-wrap');
            const checklistContainer = document.getElementById('checklist-container');

            btn.disabled = true;
            issuesContainer.style.display = 'none';
            issuesList.innerHTML = '';
            checklistContainer.innerHTML = '';
            currentCheckElement = null;
            
            currentDisplayedScore = 0;
            scoreText.innerText = '0';
            const initialColor = getColorForScore(0);
            setFillColor(initialColor);
            setProgress(0);
            
            statusText.innerHTML = "Audit running... <br><span style='font-size:0.8em; color:var(--accent-color)'>Connecting to OpenClaw</span>";
            statusText.style.color = 'var(--text-color)';
            circleWrap.classList.add('pulsing-circle');

            const eventSource = new EventSource('/stream?t=' + Date.now());
            
            let totalChecks = 0;
            let currentCheck = 0;

            eventSource.onmessage = function(event) {
                const data = JSON.parse(event.data);

                if (data.type === 'start') {
                    totalChecks = data.total;
                } else if (data.type === 'progress') {
                    addChecklistItem(data.check);
                    statusText.innerHTML = "Audit running... <br><span style='font-size:0.8em; color:var(--pulse-color)'>" + data.check + "</span>";
                } else if (data.type === 'result') {
                    currentCheck++;
                    updateCurrentChecklist(data.status);

                    const percent = Math.round((currentCheck / totalChecks) * 100);
                    setProgress(percent);
                    animateScoreTo(percent);
                    
                    const currentColor = getColorForScore(percent);
                    setFillColor(currentColor);
                    
                } else if (data.type === 'complete') {
                    circleWrap.classList.remove('pulsing-circle');
                    
                    animateScoreTo(data.score);
                    setProgress(data.score);

                    const finalColor = getColorForScore(data.score);
                    setFillColor(finalColor);

                    if (data.score === 100) {
                        statusText.innerHTML = "Your security score: <strong>" + data.score + "</strong><br><br><span style='font-size:1.3em; color: var(--success-color);'>✅ You are safe</span>";
                    } else {
                        statusText.innerHTML = "Your security score: <strong>" + data.score + "</strong><br><br><span style='font-size:1.3em; color: var(--error-color);'>⚠️ Action required</span>";
                        
                        issuesContainer.style.display = 'block';
                        data.issues.forEach(issue => {
                            const card = document.createElement('div');
                            card.className = 'issue-card';
                            card.innerHTML = `
                                <div class="issue-title">${issue.issue}</div>
                                <div class="prompt-box">${issue.prompt}</div>
                                <button class="copy-btn" onclick="copyToClipboard('${issue.prompt.replace(/'/g, "\\'")}', this)">Copy Prompt for Gemini CLI</button>
                            `;
                            issuesList.appendChild(card);
                        });
                    }

                    btn.disabled = false;
                    btn.innerText = "Run Again";
                    eventSource.close();
                }
            };

            eventSource.onerror = function() {
                circleWrap.classList.remove('pulsing-circle');
                statusText.innerText = "Error connecting to audit service.";
                statusText.style.color = 'var(--error-color)';
                setFillColor('var(--error-color)');
                if (currentCheckElement) {
                    updateCurrentChecklist('fail');
                }
                btn.disabled = false;
                eventSource.close();
            };
        }
    </script>
</body>
</html>"""

def run_cmd(cmd):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res.stdout, res.stderr, res.returncode

def get_checks():
    return [
        {"id": "ssh_port", "name": "Verifying SSH Custom Port (2244)"},
        {"id": "ssh_auth", "name": "Verifying SSH Password Auth Disabled"},
        {"id": "ssh_root", "name": "Verifying SSH Root Login Restrictions"},
        {"id": "fail2ban", "name": "Verifying Fail2ban Service"},
        {"id": "ufw", "name": "Verifying Host Firewall (UFW)"},
        {"id": "docker_user", "name": "Verifying Docker Network Isolation (DOCKER-USER)"},
        {"id": "docker_sock", "name": "Verifying Docker Socket is Unmounted"},
        {"id": "bwrap", "name": "Verifying Sandbox Engine (bubblewrap)"},
        {"id": "vault", "name": "Verifying Vault Secret Management"},
        {"id": "config_secrets", "name": "Verifying No Hardcoded Tokens in Config"},
        {"id": "config_sandbox", "name": "Verifying Config: Sandbox All"},
        {"id": "config_tools", "name": "Verifying Config: Dangerous Tools Denied"},
        {"id": "config_rate", "name": "Verifying Config: Rate Limiting"},
        {"id": "config_mdns", "name": "Verifying Config: mDNS Disabled"},
        {"id": "config_log", "name": "Verifying Config: Sensitive Logs Redacted"},
        {"id": "crowdsec", "name": "Verifying CrowdSec Engine Status"},
        {"id": "ssh_alert", "name": "Verifying SSH Alert Bot Hook"},
        {"id": "perms_dir", "name": "Verifying Workspace Permissions (.openclaw)"},
        {"id": "perms_file", "name": "Verifying Configuration Security (openclaw.json)"},
        {"id": "hsts", "name": "Verifying Nginx HSTS Configuration"},
        {"id": "xcto", "name": "Verifying Nginx Content-Type-Options"},
        {"id": "xfo", "name": "Verifying Nginx X-Frame-Options"},
        {"id": "xxss", "name": "Verifying Nginx XSS Protection"},
        {"id": "internal", "name": "Executing Deep OpenClaw Container Audit"}
    ]

def evaluate_check(check):
    success = False
    issue_text = ""
    fix_prompt = ""
    
    # Load config
    oc_config = {}
    try:
        with open('/docker/openclaw-3g02/data/.openclaw/openclaw.json', 'r') as f:
            oc_config = json.load(f)
    except:
        pass
    
    # 1. Evaluate
    if check['id'] == 'ssh_port':
        out, err, code = run_cmd("sshd -T | grep -i port")
        if "port 2244" in out.lower():
            success = True
        else:
            success = False
            issue_text = "SSH Port is not set to 2244."
            fix_prompt = "Change SSH port to 2244 in /etc/ssh/sshd_config and restart sshd."
    elif check['id'] == 'ssh_auth':
        out, err, code = run_cmd("sshd -T | grep -i passwordauthentication")
        if "passwordauthentication no" in out.lower():
            success = True
        else:
            success = False
            issue_text = "SSH Password Authentication is enabled."
            fix_prompt = "Set PasswordAuthentication no in /etc/ssh/sshd_config and restart ssh."
    elif check['id'] == 'ssh_root':
        out, err, code = run_cmd("sshd -T | grep -i permitrootlogin")
        if "prohibit-password" in out.lower() or "without-password" in out.lower() or "no" in out.lower():
            success = True
        else:
            success = False
            issue_text = "Root login is fully allowed via SSH."
            fix_prompt = "Set PermitRootLogin prohibit-password in /etc/ssh/sshd_config."
    elif check['id'] == 'fail2ban':
        out, err, code = run_cmd("systemctl is-active fail2ban")
        if "active" in out:
            success = True
        else:
            success = False
            issue_text = "Fail2ban is not active."
            fix_prompt = "Install and enable fail2ban on the VPS."
    elif check['id'] == 'ufw':
        out, err, code = run_cmd("ufw status")
        if "Status: active" in out:
            success = True
        else:
            success = False
            issue_text = "UFW Firewall is not active."
            fix_prompt = "Run `ufw enable` on the VPS."
    elif check['id'] == 'docker_user':
        out, err, code = run_cmd("iptables -L DOCKER-USER -n")
        if "DROP" in out:
            success = True
        else:
            success = False
            issue_text = "DOCKER-USER isolation rules missing in iptables."
            fix_prompt = "Add DROP rules to the DOCKER-USER iptables chain to prevent UFW bypass by Docker."
    elif check['id'] == 'docker_sock':
        out, err, code = run_cmd("docker inspect openclaw-3g02-openclaw-1 --format '{{json .Mounts}}'")
        if "docker.sock" not in out:
            success = True
        else:
            success = False
            issue_text = "docker.sock is mounted in the container."
            fix_prompt = "Remove /var/run/docker.sock mount from the OpenClaw container configuration."
    elif check['id'] == 'bwrap':
        out, err, code = run_cmd("docker exec openclaw-3g02-openclaw-1 which bwrap")
        if out.strip():
            success = True
        else:
            success = False
            issue_text = "Bubblewrap (bwrap) not found in container."
            fix_prompt = "Install bubblewrap in the OpenClaw container."
    elif check['id'] == 'vault':
        out, err, code = run_cmd("ls /usr/local/bin/vault.sh || ls /root/vault.sh || true")
        if "vault.sh" in out:
            success = True
        else:
            success = False
            issue_text = "vault.sh secret manager not found."
            fix_prompt = "Install the vault.sh script for dynamic secret injection."
    elif check['id'] == 'config_secrets':
        channels = oc_config.get("channels", {})
        tg_token = channels.get("telegram", {}).get("botToken", "")
        if "${" in tg_token or not tg_token:
            success = True
        else:
            success = False
            issue_text = "Hardcoded Telegram bot token found in config."
            fix_prompt = "Replace the hardcoded botToken with '${TELEGRAM_BOT_TOKEN}' in openclaw.json."
    elif check['id'] == 'config_sandbox':
        sandbox_mode = oc_config.get("agents", {}).get("defaults", {}).get("sandbox", {}).get("mode", "")
        if sandbox_mode == "all":
            success = True
        else:
            success = False
            issue_text = "Default sandbox mode is not set to 'all'."
            fix_prompt = "Set agents.defaults.sandbox.mode to 'all' in openclaw.json."
    elif check['id'] == 'config_tools':
        deny_tools = oc_config.get("tools", {}).get("deny", [])
        if "exec" in deny_tools and "bash" in deny_tools:
            success = True
        else:
            success = False
            issue_text = "Dangerous tools (exec, bash) are not denied globally."
            fix_prompt = "Add 'exec' and 'bash' to tools.deny in openclaw.json."
    elif check['id'] == 'config_rate':
        rate_limit = oc_config.get("gateway", {}).get("auth", {}).get("rateLimit")
        if rate_limit is not None and rate_limit is not False:
            success = True
        else:
            success = False
            issue_text = "Gateway rate limiting is disabled."
            fix_prompt = "Set gateway.auth.rateLimit to {} in openclaw.json."
    elif check['id'] == 'config_mdns':
        mdns_mode = oc_config.get("discovery", {}).get("mdns", {}).get("mode", "")
        if mdns_mode == "off":
            success = True
        else:
            success = False
            issue_text = "mDNS discovery is not disabled."
            fix_prompt = "Set discovery.mdns.mode to 'off' in openclaw.json."
    elif check['id'] == 'config_log':
        redact = oc_config.get("logging", {}).get("redactSensitive", "")
        if redact == "tools":
            success = True
        else:
            success = False
            issue_text = "Sensitive tool logging is not redacted."
            fix_prompt = "Set logging.redactSensitive to 'tools' in openclaw.json."
    elif check['id'] == 'crowdsec':
        out, err, code = run_cmd("systemctl is-active crowdsec")
        if "active" in out:
            success = True
        else:
            success = False
            issue_text = "CrowdSec engine is not active."
            fix_prompt = "Install and enable CrowdSec on the VPS."
    elif check['id'] == 'ssh_alert':
        out, err, code = run_cmd("cat /etc/ssh/sshrc || true")
        if "curl" in out or "wget" in out:
            success = True
        else:
            success = False
            issue_text = "SSH alert hook not found in /etc/ssh/sshrc."
            fix_prompt = "Add an SSH alert webhook script to /etc/ssh/sshrc."
    elif check['id'] in ['hsts', 'xcto', 'xfo', 'xxss']:
        out, err, code = run_cmd("curl -I -s https://localhost --insecure || curl -I -s http://localhost")
        header_map = {
            'hsts': 'Strict-Transport-Security',
            'xcto': 'X-Content-Type-Options',
            'xfo': 'X-Frame-Options',
            'xxss': 'X-XSS-Protection'
        }
        h = header_map[check['id']]
        if h in out:
            success = True
        else:
            success = False
            issue_text = f"Missing Nginx header: {h}"
            fix_prompt = f"Add `{h}` header to the Nginx configuration."
    elif check['id'] == 'perms_dir':
        out, err, code = run_cmd("ls -ld /docker/openclaw-3g02/data/.openclaw")
        if "drwx------" in out:
            success = True
        else:
            success = False
            issue_text = "Incorrect permissions on .openclaw directory (should be 700)."
            fix_prompt = "Run `chmod 700 /docker/openclaw-3g02/data/.openclaw` on the VPS."
    elif check['id'] == 'perms_file':
        out, err, code = run_cmd("ls -l /docker/openclaw-3g02/data/.openclaw/openclaw.json")
        if "-rw-------" in out:
            success = True
        else:
            success = False
            issue_text = "Incorrect permissions on openclaw.json (should be 600)."
            fix_prompt = "Run `chmod 600 /docker/openclaw-3g02/data/.openclaw/openclaw.json` on the VPS."
    elif check['id'] == 'internal':
        out, err, code = run_cmd("docker exec openclaw-3g02-openclaw-1 openclaw security audit")
        if "0 critical" in out and "0 warn" in out:
            success = True
        elif "0 critical" in out:
            if "WARN" in out and "trusted_proxies_missing" not in out:
                success = False
                issue_text = "Internal Audit reported warnings/criticals."
                fix_prompt = "Run `docker exec openclaw-3g02-openclaw-1 openclaw security audit --deep` and fix the reported issues."
            else:
                success = True
        else:
            success = False
            issue_text = "Internal Audit reported critical issues."
            fix_prompt = "Run `docker exec openclaw-3g02-openclaw-1 openclaw security audit --deep` and fix the reported issues."
    
    return success, issue_text, fix_prompt

def run_cli_audit():
    print("=" * 60)
    print(" 🛡️  OpenClaw Security Audit (CLI Mode) ".center(60))
    print("=" * 60 + "\\n")
    
    checks = get_checks()
    passed = 0
    issues = []
    
    for check in checks:
        print(f"[*] {check['name']}... ", end="", flush=True)
        time.sleep(0.2)
        success, issue_text, fix_prompt = evaluate_check(check)
        
        if success:
            print("\\033[92mPASS\\033[0m")
            passed += 1
        else:
            print("\\033[91mFAIL\\033[0m")
            issues.append({"name": check["name"], "issue": issue_text, "fix": fix_prompt})

    score = int((passed / len(checks)) * 100)
    print("\\n" + "=" * 60)
    
    color = "\\033[92m" if score == 100 else "\\033[93m" if score >= 75 else "\\033[91m"
    print(f"Final Security Score: {color}{score}/100\\033[0m")
    
    if score == 100:
        print("\\n✅ You are safe! No vulnerabilities found.")
    else:
        print("\\n⚠️  Action required. The following issues were found:\\n")
        for i, iss in enumerate(issues, 1):
            print(f"  {i}. {iss['name']}")
            print(f"     Issue: {iss['issue']}")
            print(f"     Prompt to fix: {iss['fix']}\\n")

def run_web_audit(port):
    try:
        from flask import Flask, Response, render_template_string
    except ImportError:
        print("Error: Flask is not installed.")
        print("Run: pip install flask")
        sys.exit(1)
        
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return render_template_string(HTML_CONTENT)
        
    @app.route('/stream')
    def stream():
        def generate():
            checks = get_checks()
            yield f"data: {json.dumps({'type': 'start', 'total': len(checks)})}\\n\\n"
            
            passed = 0
            issues = []
            
            for check in checks:
                yield f"data: {json.dumps({'type': 'progress', 'check': check['name']})}\\n\\n"
                time.sleep(0.3)
                
                success, issue_text, fix_prompt = evaluate_check(check)
                if success:
                    passed += 1
                    yield f"data: {json.dumps({'type': 'result', 'id': check['id'], 'status': 'pass'})}\\n\\n"
                else:
                    issues.append({'issue': issue_text, 'prompt': fix_prompt})
                    yield f"data: {json.dumps({'type': 'result', 'id': check['id'], 'status': 'fail'})}\\n\\n"
                    
            score = int((passed / len(checks)) * 100)
            yield f"data: {json.dumps({'type': 'complete', 'score': score, 'issues': issues})}\\n\\n"
            
        return Response(generate(), mimetype='text/event-stream')

    print(f"\\n🚀 Starting OpenClaw Audit Web Dashboard on port {port}...")
    print(f"   Access it at http://<your-vps-ip>:{port}/")
    print("   Press CTRL+C to quit.\\n")
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OpenClaw Security Audit Tool")
    parser.add_argument("--web", action="store_true", help="Start the Web Dashboard instead of CLI")
    parser.add_argument("--port", type=int, default=8021, help="Port for the Web Dashboard (default: 8021)")
    
    args = parser.parse_args()
    
    if args.web:
        run_web_audit(args.port)
    else:
        run_cli_audit()