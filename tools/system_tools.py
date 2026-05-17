import os, platform, subprocess, re, hashlib

def tool_sys_info(p):
    import platform, os, subprocess
    info = {
        'Platform'  : platform.system(),
        'Release'   : platform.release(),
        'Version'   : platform.version()[:60],
        'Machine'   : platform.machine(),
        'Processor' : platform.processor() or 'N/A',
        'Python'    : platform.python_version(),
        'Hostname'  : platform.node(),
        'CPU Count' : os.cpu_count(),
    }
    output = [f"[*] System Information\n{'─'*40}"]
    for k, v in info.items():
        output.append(f"  {k:<12}: {v}")
    return '\n'.join(output)

def tool_process_list(p):
    try:
        r = subprocess.run(['ps','aux','--sort=-%cpu'], capture_output=True, text=True, timeout=5)
        lines = r.stdout.strip().split('\n')[:25]
        return "[*] Process List (Top 25)\n" + '─'*40 + '\n' + '\n'.join(lines)
    except Exception as e:
        return f"[!] {e}"

def tool_disk_usage(p):
    try:
        r = subprocess.run(['df','-h'], capture_output=True, text=True)
        return "[*] Disk Usage\n" + '─'*40 + '\n' + r.stdout
    except Exception as e:
        return f"[!] {e}"

def tool_net_interfaces(p):
    try:
        r = subprocess.run(['ip','addr'], capture_output=True, text=True)
        if not r.stdout:
            r = subprocess.run(['ifconfig'], capture_output=True, text=True)
        return "[*] Network Interfaces\n" + '─'*40 + '\n' + r.stdout
    except Exception as e:
        return f"[!] {e}"

def tool_env_vars(p):
    output = ["[*] Environment Variables\n" + '─'*40]
    for k, v in sorted(os.environ.items())[:40]:
        output.append(f"  {k:<25}: {v[:80]}")
    return '\n'.join(output)

def tool_file_hash(p):
    path = p.get('path','').strip()
    if not path: return "[!] Provide a file path."
    if not os.path.exists(path): return f"[!] File not found: {path}"
    try:
        d = open(path,'rb').read()
        return (f"[*] File Hash: {path}\n{'─'*40}\n"
                f"  MD5    : {hashlib.md5(d).hexdigest()}\n"
                f"  SHA1   : {hashlib.sha1(d).hexdigest()}\n"
                f"  SHA256 : {hashlib.sha256(d).hexdigest()}\n"
                f"  Size   : {len(d):,} bytes")
    except Exception as e:
        return f"[!] {e}"

def tool_log_analyze(p):
    log = p.get('log','').strip()
    if not log: return "[!] Paste log content."
    lines    = log.split('\n')
    errors   = [l for l in lines if 'error' in l.lower()]
    warnings = [l for l in lines if 'warn' in l.lower()]
    ips      = list(set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', log)))
    out = [f"[*] Log Analyzer\n{'─'*40}",
           f"  Total Lines : {len(lines)}",
           f"  Errors      : {len(errors)}",
           f"  Warnings    : {len(warnings)}",
           f"  Unique IPs  : {len(ips)}"]
    if ips:
        out.append("\n  IPs Found:")
        for ip in ips[:20]: out.append(f"    {ip}")
    if errors:
        out.append("\n  Error Lines:")
        for e in errors[:10]: out.append(f"    {e[:100]}")
    return '\n'.join(out)

def tool_firewall_check(p):
    try:
        r = subprocess.run(['iptables','-L','-n'], capture_output=True, text=True, timeout=8)
        if r.returncode == 0 and r.stdout:
            return "[*] Firewall (iptables)\n" + '─'*40 + '\n' + r.stdout[:3000]
        r2 = subprocess.run(['ufw','status','verbose'], capture_output=True, text=True)
        return "[*] Firewall (ufw)\n" + '─'*40 + '\n' + r2.stdout
    except Exception as e:
        return f"[!] Firewall info requires root or is unavailable: {e}"
