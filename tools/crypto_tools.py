import hashlib
import base64
import os
import sys
import platform
import subprocess
import string
import random
import struct
import json

# ══════════════════════════════════════════════════════════════
#  CRYPTO TOOLS
# ══════════════════════════════════════════════════════════════

def tool_md5(p):
    text = p.get('text', '')
    h = hashlib.md5(text.encode()).hexdigest()
    return f"[*] MD5 Hash\n{'─'*40}\n  Input : {text[:60]}\n  Hash  : {h}"

def tool_sha1(p):
    text = p.get('text', '')
    h = hashlib.sha1(text.encode()).hexdigest()
    return f"[*] SHA-1 Hash\n{'─'*40}\n  Input : {text[:60]}\n  Hash  : {h}"

def tool_sha256(p):
    text = p.get('text', '')
    h = hashlib.sha256(text.encode()).hexdigest()
    return f"[*] SHA-256 Hash\n{'─'*40}\n  Input : {text[:60]}\n  Hash  : {h}"

def tool_sha512(p):
    text = p.get('text', '')
    h = hashlib.sha512(text.encode()).hexdigest()
    return f"[*] SHA-512 Hash\n{'─'*40}\n  Input : {text[:60]}\n  Hash  : {h}"

def tool_base64_encode(p):
    text = p.get('text', '')
    enc = base64.b64encode(text.encode()).decode()
    return f"[*] Base64 Encoded\n{'─'*40}\n  Input  : {text[:60]}\n  Output : {enc}"

def tool_base64_decode(p):
    text = p.get('text', '').strip()
    try:
        dec = base64.b64decode(text + '==').decode()
        return f"[*] Base64 Decoded\n{'─'*40}\n  Input  : {text[:60]}\n  Output : {dec}"
    except Exception as e:
        return f"[!] Base64 decode error: {e}"

def tool_caesar(p):
    text = p.get('text', '')
    shift = int(p.get('shift', 13))
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    enc = ''.join(result)
    return f"[*] Caesar Cipher (shift={shift})\n{'─'*40}\n  Input  : {text}\n  Output : {enc}"

def tool_rot13(p):
    text = p.get('text', '')
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return f"[*] ROT13\n{'─'*40}\n  Input  : {text}\n  Output : {''.join(result)}"

def tool_hex_encode(p):
    text = p.get('text', '')
    enc = text.encode().hex()
    return f"[*] Hex Encode\n{'─'*40}\n  Input  : {text[:60]}\n  Output : {enc}"

def tool_hex_decode(p):
    text = p.get('text', '').strip().replace(' ', '')
    try:
        dec = bytes.fromhex(text).decode(errors='replace')
        return f"[*] Hex Decode\n{'─'*40}\n  Input  : {text[:60]}\n  Output : {dec}"
    except Exception as e:
        return f"[!] Hex decode error: {e}"

def tool_jwt_decode(p):
    token = p.get('token', '').strip()
    if not token:
        return "[!] Please provide a JWT token."
    parts = token.split('.')
    if len(parts) != 3:
        return "[!] Invalid JWT format. Expected: header.payload.signature"
    output = [f"[*] JWT Decoder\n{'─'*40}"]
    labels = ['Header', 'Payload']
    for i, label in enumerate(labels):
        try:
            pad = parts[i] + '=' * (4 - len(parts[i]) % 4)
            decoded = base64.b64decode(pad).decode()
            data = json.loads(decoded)
            output.append(f"\n  ─── {label} ───")
            for k, v in data.items():
                output.append(f"  {k:<16}: {v}")
        except Exception as e:
            output.append(f"  [{label}] Decode error: {e}")
    output.append(f"\n  ─── Signature ───")
    output.append(f"  {parts[2][:40]}...")
    output.append("\n[!] Signature NOT verified (no secret key).")
    return '\n'.join(output)

def tool_pass_strength(p):
    pw = p.get('password', '')
    if not pw:
        return "[!] Please provide a password."
    score = 0
    checks = {
        'Length ≥ 8'       : len(pw) >= 8,
        'Length ≥ 12'      : len(pw) >= 12,
        'Length ≥ 16'      : len(pw) >= 16,
        'Uppercase letter' : any(c.isupper() for c in pw),
        'Lowercase letter' : any(c.islower() for c in pw),
        'Digit'            : any(c.isdigit() for c in pw),
        'Special char'     : any(c in string.punctuation for c in pw),
        'No common words'  : pw.lower() not in ['password','123456','admin','qwerty','letmein'],
    }
    output = [f"[*] Password Strength\n{'─'*40}"]
    for k, v in checks.items():
        mark = '✔' if v else '✘'
        score += v
        output.append(f"  [{mark}] {k}")
    level = ['Very Weak','Weak','Fair','Good','Strong','Very Strong','Excellent','Excellent','Excellent'][min(score,8)]
    output.append(f"\n  Score : {score}/{len(checks)}")
    output.append(f"  Level : {level}")
    return '\n'.join(output)

def tool_pass_gen(p):
    length = min(int(p.get('length', 16)), 64)
    use_upper  = p.get('upper', True)
    use_lower  = p.get('lower', True)
    use_digits = p.get('digits', True)
    use_sym    = p.get('symbols', True)
    chars = ''
    if use_upper:  chars += string.ascii_uppercase
    if use_lower:  chars += string.ascii_lowercase
    if use_digits: chars += string.digits
    if use_sym:    chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    if not chars:  chars = string.ascii_letters + string.digits
    pw = ''.join(random.SystemRandom().choice(chars) for _ in range(length))
    return f"[*] Password Generator\n{'─'*40}\n  Length   : {length}\n  Password : {pw}"

def tool_hash_crack(p):
    hash_val = p.get('hash', '').strip().lower()
    if not hash_val:
        return "[!] Please provide a hash to crack."
    WORDLIST = ['password','123456','admin','qwerty','letmein','welcome','monkey',
                'dragon','master','sunshine','princess','shadow','superman','batman',
                'football','baseball','soccer','abc123','pass','1234','test','root',
                'toor','default','guest','user','login','hello','world','secret']
    hash_len = len(hash_val)
    algo_map = {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}
    algo = algo_map.get(hash_len)
    if not algo:
        return f"[!] Unknown hash type (length {hash_len}). Expected MD5/SHA1/SHA256/SHA512."
    output = [f"[*] Hash Cracker ({algo.upper()})\n{'─'*40}\n  Hash: {hash_val}\n"]
    for word in WORDLIST:
        h = getattr(hashlib, algo)(word.encode()).hexdigest()
        if h == hash_val:
            return '\n'.join(output) + f"  [+] CRACKED! → {word!r}"
        output.append(f"  [ ] Tried: {word}")
    return '\n'.join(output) + f"\n  [-] Not found in wordlist ({len(WORDLIST)} words)."

def tool_xor_cipher(p):
    text = p.get('text', '')
    key  = p.get('key', 'A')
    if not key: key = 'A'
    out = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))
    enc_hex = out.encode(errors='replace').hex()
    return f"[*] XOR Cipher\n{'─'*40}\n  Input  : {text[:60]}\n  Key    : {key}\n  Output (hex): {enc_hex}"


# ══════════════════════════════════════════════════════════════
#  SYSTEM TOOLS
# ══════════════════════════════════════════════════════════════

def tool_sys_info(p):
    info = {
        'Platform'   : platform.system(),
        'Release'    : platform.release(),
        'Version'    : platform.version()[:60],
        'Machine'    : platform.machine(),
        'Processor'  : platform.processor() or 'N/A',
        'Python'     : platform.python_version(),
        'Hostname'   : platform.node(),
        'CPU Count'  : os.cpu_count(),
    }
    output = [f"[*] System Information\n{'─'*40}"]
    for k, v in info.items():
        output.append(f"  {k:<12}: {v}")
    try:
        uname = subprocess.run(['uname', '-a'], capture_output=True, text=True)
        output.append(f"\n  Uname    : {uname.stdout.strip()}")
    except: pass
    return '\n'.join(output)

def tool_process_list(p):
    try:
        result = subprocess.run(['ps', 'aux', '--sort=-%cpu'],
                                capture_output=True, text=True, timeout=5)
        lines = result.stdout.strip().split('\n')[:25]
        return f"[*] Process List (Top 25 by CPU)\n{'─'*40}\n" + '\n'.join(lines)
    except Exception as e:
        return f"[!] Error: {e}"

def tool_disk_usage(p):
    try:
        result = subprocess.run(['df', '-h'], capture_output=True, text=True)
        return f"[*] Disk Usage\n{'─'*40}\n{result.stdout}"
    except Exception as e:
        return f"[!] Error: {e}"

def tool_net_interfaces(p):
    try:
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
        if result.returncode != 0:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
        return f"[*] Network Interfaces\n{'─'*40}\n{result.stdout}"
    except Exception as e:
        return f"[!] Error: {e}"

def tool_env_vars(p):
    output = [f"[*] Environment Variables\n{'─'*40}"]
    for k, v in sorted(os.environ.items())[:40]:
        val = v[:80] if len(v) > 80 else v
        output.append(f"  {k:<25}: {val}")
    return '\n'.join(output)

def tool_file_hash(p):
    path = p.get('path', '').strip()
    if not path:
        return "[!] Please provide a file path."
    if not os.path.exists(path):
        return f"[!] File not found: {path}"
    try:
        with open(path, 'rb') as f:
            data = f.read()
        return (f"[*] File Hash: {path}\n{'─'*40}\n"
                f"  MD5    : {hashlib.md5(data).hexdigest()}\n"
                f"  SHA1   : {hashlib.sha1(data).hexdigest()}\n"
                f"  SHA256 : {hashlib.sha256(data).hexdigest()}\n"
                f"  Size   : {len(data):,} bytes")
    except Exception as e:
        return f"[!] Error: {e}"

def tool_log_analyze(p):
    log_text = p.get('log', '').strip()
    if not log_text:
        return "[!] Please paste log content."
    lines = log_text.split('\n')
    errors   = [l for l in lines if 'error' in l.lower()]
    warnings = [l for l in lines if 'warn' in l.lower()]
    ips      = list(set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', log_text)))
    output   = [f"[*] Log Analyzer\n{'─'*40}",
                f"  Total Lines : {len(lines)}",
                f"  Errors      : {len(errors)}",
                f"  Warnings    : {len(warnings)}",
                f"  Unique IPs  : {len(ips)}",
                f"\n  ─── IPs Found ───"]
    for ip in ips[:20]: output.append(f"  {ip}")
    if errors:
        output.append(f"\n  ─── Error Lines ───")
        for e in errors[:10]: output.append(f"  {e[:100]}")
    return '\n'.join(output)

def tool_firewall_check(p):
    try:
        result = subprocess.run(['iptables', '-L', '-n', '--line-numbers'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return f"[*] Firewall Rules (iptables)\n{'─'*40}\n{result.stdout[:3000]}"
        else:
            result2 = subprocess.run(['ufw', 'status', 'verbose'],
                                     capture_output=True, text=True, timeout=5)
            return f"[*] Firewall Rules (ufw)\n{'─'*40}\n{result2.stdout}"
    except Exception as e:
        return f"[!] Could not read firewall rules (may need root): {e}"

import re  # re needed for log_analyze
