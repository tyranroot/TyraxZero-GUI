import urllib.request
import urllib.parse
import urllib.error
import http.client
import ssl
import socket
import re
import json
import time

UA = 'Mozilla/5.0 (X11; Linux x86_64) CyberKit/1.0'

def _fetch(url, timeout=8, method='GET'):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': UA}, method=method)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r, r.read().decode(errors='ignore'), r.info()
    except Exception as e:
        return None, None, str(e)

# ── HTTP Headers ──────────────────────────────────────────────────────────────
def tool_http_headers(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': UA})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            headers = dict(r.info())
        output = [f"[*] HTTP Headers: {url}\n{'─'*40}"]
        for k, v in sorted(headers.items()):
            output.append(f"  {k:<30}: {v}")
        # Security header check
        sec = ['x-frame-options','x-xss-protection','x-content-type-options',
               'strict-transport-security','content-security-policy']
        output.append(f"\n[*] Security Headers:")
        for h in sec:
            if h in {k.lower() for k in headers}:
                output.append(f"  [✔] {h}")
            else:
                output.append(f"  [✘] {h}  (MISSING)")
        return '\n'.join(output)
    except Exception as e:
        return f"[!] Error: {e}"


# ── Robots.txt ────────────────────────────────────────────────────────────────
def tool_robots_txt(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    if not url.startswith('http'):
        url = 'http://' + url
    base = url.rstrip('/')
    _, body, err = _fetch(f"{base}/robots.txt")
    if body:
        return f"[*] robots.txt: {base}/robots.txt\n{'─'*40}\n{body[:2000]}"
    return f"[!] Could not fetch robots.txt: {err}"


# ── Sitemap ───────────────────────────────────────────────────────────────────
def tool_sitemap(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    if not url.startswith('http'):
        url = 'http://' + url
    base = url.rstrip('/')
    candidates = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap.txt', '/sitemap/']
    for path in candidates:
        _, body, _ = _fetch(f"{base}{path}")
        if body and len(body) > 10:
            urls = re.findall(r'<loc>(.*?)</loc>', body)
            out = [f"[*] Sitemap found: {base}{path}\n{'─'*40}"]
            for u in urls[:30]:
                out.append(f"  {u}")
            if len(urls) > 30:
                out.append(f"  ... and {len(urls)-30} more")
            return '\n'.join(out)
    return f"[!] No sitemap found at common paths for {base}"


# ── Directory Brute Force ─────────────────────────────────────────────────────
def tool_dir_bruteforce(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    if not url.startswith('http'):
        url = 'http://' + url
    base = url.rstrip('/')
    WORDLIST = [
        'admin','login','dashboard','wp-admin','config','backup',
        'api','v1','v2','test','dev','staging','old','new','tmp',
        'upload','uploads','files','images','assets','static',
        '.git','phpinfo.php','info.php','robots.txt','sitemap.xml',
        'index.php','index.html','wp-config.php','readme.html',
        'administrator','manager','portal','panel','console',
        'phpmyadmin','db','database','sql','shell','cmd'
    ]
    output = [f"[*] Dir Brute-Force: {base}\n{'─'*40}"]
    found = []
    for word in WORDLIST:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(f"{base}/{word}", headers={'User-Agent': UA})
            with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
                code = r.status
            if code < 400:
                output.append(f"  [{code}] /{word}")
                found.append(word)
        except urllib.error.HTTPError as e:
            if e.code in [301, 302, 403]:
                output.append(f"  [{e.code}] /{word}")
                found.append(word)
        except:
            pass
    output.append(f"\n[*] Found {len(found)} path(s).")
    return '\n'.join(output)


# ── SQLi Test ─────────────────────────────────────────────────────────────────
def tool_sqli_test(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL with parameters (e.g. http://site.com/page?id=1)."
    payloads = ["'", '"', "1'", "1 OR 1=1", "' OR '1'='1", "'; DROP TABLE users;--",
                "1; SELECT sleep(2)--", "' AND 1=2--", "admin'--"]
    errors = ['sql syntax','mysql_fetch','mysqli_','pg_query','sqlite_','ORA-',
              'syntax error','unclosed quotation','ODBC Driver']
    output = [f"[*] SQLi Test: {url}\n{'─'*40}"]
    for payload in payloads:
        test_url = url + urllib.parse.quote(payload) if '?' not in url else url + urllib.parse.quote(payload)
        try:
            _, body, _ = _fetch(test_url, timeout=5)
            if body:
                found = [e for e in errors if e.lower() in body.lower()]
                if found:
                    output.append(f"  [!] POTENTIAL SQLi → payload: {payload!r}")
                    output.append(f"       Error string: {found[0]}")
                else:
                    output.append(f"  [ ] {payload!r:30s} → no error")
        except:
            pass
    output.append(f"\n[!] Always verify manually. This is a basic heuristic test.")
    return '\n'.join(output)


# ── XSS Scanner ───────────────────────────────────────────────────────────────
def tool_xss_scan(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "';alert(1)//",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '{{7*7}}', '${7*7}'
    ]
    output = [f"[*] XSS Scanner: {url}\n{'─'*40}"]
    for payload in payloads:
        test_url = url + urllib.parse.quote(payload)
        try:
            _, body, _ = _fetch(test_url, timeout=5)
            if body and (payload in body or urllib.parse.unquote(payload) in body):
                output.append(f"  [!] REFLECTED → {payload!r}")
            else:
                output.append(f"  [ ] Not reflected: {repr(payload)[:50]}")
        except:
            pass
    return '\n'.join(output)


# ── SSL Checker ───────────────────────────────────────────────────────────────
def tool_ssl_check(p):
    host = p.get('host', '').strip()
    port = int(p.get('port', 443))
    if not host:
        return "[!] Please provide a host."
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(8)
            s.connect((host, port))
            cert = s.getpeercert()
        output = [f"[*] SSL Certificate: {host}:{port}\n{'─'*40}"]
        output.append(f"  Subject  : {dict(x[0] for x in cert['subject'])}")
        output.append(f"  Issuer   : {dict(x[0] for x in cert['issuer'])}")
        output.append(f"  Version  : {cert.get('version')}")
        output.append(f"  Valid From : {cert.get('notBefore')}")
        output.append(f"  Valid To   : {cert.get('notAfter')}")
        sans = cert.get('subjectAltName', [])
        if sans:
            output.append(f"  SANs     : {', '.join(v for _,v in sans)}")
        return '\n'.join(output)
    except ssl.SSLCertVerificationError as e:
        return f"[!] SSL Verification Error: {e}"
    except Exception as e:
        return f"[!] Error: {e}"


# ── URL Encode/Decode ─────────────────────────────────────────────────────────
def tool_url_encode(p):
    text = p.get('text', '')
    return f"[*] URL Encoded:\n{'─'*40}\n{urllib.parse.quote(text)}"

def tool_url_decode(p):
    text = p.get('text', '')
    return f"[*] URL Decoded:\n{'─'*40}\n{urllib.parse.unquote(text)}"


# ── HTTP Methods ──────────────────────────────────────────────────────────────
def tool_http_methods(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    if not url.startswith('http'):
        url = 'http://' + url
    methods = ['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD','TRACE']
    output = [f"[*] HTTP Method Test: {url}\n{'─'*40}"]
    for method in methods:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={'User-Agent': UA}, method=method)
            with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                output.append(f"  {method:<8} → {r.status} {r.reason}")
        except urllib.error.HTTPError as e:
            output.append(f"  {method:<8} → {e.code} {e.reason}")
        except Exception as e:
            output.append(f"  {method:<8} → ERROR ({str(e)[:40]})")
    return '\n'.join(output)


# ── Cookie Analyzer ───────────────────────────────────────────────────────────
def tool_cookie_analyzer(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': UA})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            raw_cookies = r.info().get_all('Set-Cookie') or []
        if not raw_cookies:
            return f"[*] No Set-Cookie headers found at {url}"
        output = [f"[*] Cookie Analysis: {url}\n{'─'*40}"]
        for c in raw_cookies:
            output.append(f"\n  Cookie: {c[:100]}")
            flags = []
            if 'HttpOnly' in c: flags.append('✔ HttpOnly')
            else: flags.append('✘ HttpOnly MISSING')
            if 'Secure' in c: flags.append('✔ Secure')
            else: flags.append('✘ Secure MISSING')
            if 'SameSite' in c: flags.append('✔ SameSite')
            else: flags.append('✘ SameSite MISSING')
            output.append(f"  Flags  : {' | '.join(flags)}")
        return '\n'.join(output)
    except Exception as e:
        return f"[!] Error: {e}"


# ── Web Crawler ───────────────────────────────────────────────────────────────
def tool_web_crawler(p):
    url = p.get('url', '').strip()
    depth = int(p.get('depth', 1))
    if not url:
        return "[!] Please provide a URL."
    if not url.startswith('http'):
        url = 'http://' + url
    visited = set()
    to_visit = [url]
    output = [f"[*] Web Crawler: {url} (depth={min(depth,2)})\n{'─'*40}"]
    base_domain = urllib.parse.urlparse(url).netloc
    for _ in range(min(depth, 2)):
        next_level = []
        for u in to_visit[:10]:
            if u in visited: continue
            visited.add(u)
            try:
                _, body, _ = _fetch(u, timeout=5)
                if body:
                    links = re.findall(r'href=["\']([^"\']+)["\']', body)
                    for link in links:
                        abs_link = urllib.parse.urljoin(u, link)
                        if urllib.parse.urlparse(abs_link).netloc == base_domain:
                            if abs_link not in visited:
                                next_level.append(abs_link)
                                output.append(f"  {abs_link}")
            except: pass
        to_visit = next_level[:20]
    output.append(f"\n[*] Crawled {len(visited)} page(s), found {len(output)-2} link(s).")
    return '\n'.join(output)


# ── CMS Detector ──────────────────────────────────────────────────────────────
def tool_cms_detect(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    if not url.startswith('http'):
        url = 'http://' + url
    _, body, headers = _fetch(url)
    if not body:
        return f"[!] Could not fetch {url}"
    detected = []
    checks = {
        'WordPress'   : ['/wp-content/', '/wp-includes/', 'wp-json'],
        'Joomla'      : ['/components/com_', 'Joomla!', '/templates/'],
        'Drupal'      : ['Drupal.settings', '/sites/default/', 'drupal.js'],
        'Magento'     : ['Mage.Cookies', '/skin/frontend/', 'mage/'],
        'Shopify'     : ['cdn.shopify.com', 'shopify.com/s/files'],
        'Wix'         : ['wix.com', 'wixstatic.com'],
        'Squarespace' : ['squarespace.com', 'static.squarespace'],
        'Django'      : ['csrfmiddlewaretoken', '__django'],
        'Laravel'     : ['laravel_session', 'Laravel'],
        'Rails'       : ['authenticity_token', 'rails-'],
    }
    for cms, patterns in checks.items():
        if any(p in body for p in patterns):
            detected.append(cms)
    output = [f"[*] CMS Detection: {url}\n{'─'*40}"]
    if detected:
        for c in detected:
            output.append(f"  [+] Detected: {c}")
    else:
        output.append("  [ ] No common CMS detected.")
    return '\n'.join(output)


# ── Email Harvester ───────────────────────────────────────────────────────────
def tool_email_harvest(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    if not url.startswith('http'):
        url = 'http://' + url
    _, body, _ = _fetch(url)
    if not body:
        return f"[!] Could not fetch {url}"
    emails = set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', body))
    output = [f"[*] Email Harvester: {url}\n{'─'*40}"]
    if emails:
        for e in sorted(emails):
            output.append(f"  [+] {e}")
        output.append(f"\n[*] Found {len(emails)} email(s).")
    else:
        output.append("  [ ] No emails found on page.")
    return '\n'.join(output)


# ── Wayback Machine ───────────────────────────────────────────────────────────
def tool_wayback(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    try:
        api = f"http://archive.org/wayback/available?url={urllib.parse.quote(url)}"
        _, body, _ = _fetch(api, timeout=8)
        if body:
            data = json.loads(body)
            snap = data.get('archived_snapshots', {}).get('closest', {})
            if snap:
                return (f"[*] Wayback Machine: {url}\n{'─'*40}\n"
                        f"  Status    : {snap.get('status')}\n"
                        f"  Available : {snap.get('available')}\n"
                        f"  Timestamp : {snap.get('timestamp')}\n"
                        f"  URL       : {snap.get('url')}")
            else:
                return f"[!] No archived snapshot found for {url}"
    except Exception as e:
        return f"[!] Error: {e}"
