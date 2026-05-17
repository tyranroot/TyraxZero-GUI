import urllib.request, urllib.parse, urllib.error
import json, re, socket, ssl, subprocess

UA = 'Mozilla/5.0 CyberKit/1.0'

def _get(url, timeout=8):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': UA})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode(errors='ignore')
    except Exception as e:
        return None

# ── Google Dork Generator ────────────────────────────────────────────────────
def tool_google_dork(p):
    domain = p.get('domain', '').strip()
    if not domain:
        return "[!] Please provide a domain."
    dorks = [
        f'site:{domain}',
        f'site:{domain} filetype:pdf',
        f'site:{domain} filetype:xls OR filetype:xlsx',
        f'site:{domain} filetype:doc OR filetype:docx',
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:login',
        f'site:{domain} inurl:config',
        f'site:{domain} inurl:backup',
        f'site:{domain} intext:password',
        f'site:{domain} intext:"index of /"',
        f'site:{domain} inurl:phpinfo.php',
        f'site:{domain} inurl:.git',
        f'site:{domain} inurl:wp-admin',
        f'site:{domain} inurl:phpmyadmin',
        f'intitle:"index of" site:{domain}',
        f'cache:{domain}',
        f'link:{domain}',
        f'related:{domain}',
        f'"@{domain}" email',
        f'site:{domain} ext:env OR ext:log OR ext:bak',
    ]
    output = [f"[*] Google Dork Generator: {domain}\n{'─'*40}",
              "[!] Copy these into Google Search:\n"]
    for d in dorks:
        encoded = urllib.parse.quote(d)
        output.append(f"  {d}")
        output.append(f"    → https://www.google.com/search?q={encoded}\n")
    return '\n'.join(output)


# ── Social Media Recon ────────────────────────────────────────────────────────
def tool_social_recon(p):
    username = p.get('username', '').strip()
    if not username:
        return "[!] Please provide a username."
    platforms = {
        'GitHub'    : f'https://github.com/{username}',
        'Twitter/X' : f'https://twitter.com/{username}',
        'Instagram' : f'https://instagram.com/{username}',
        'LinkedIn'  : f'https://linkedin.com/in/{username}',
        'Reddit'    : f'https://reddit.com/user/{username}',
        'YouTube'   : f'https://youtube.com/@{username}',
        'TikTok'    : f'https://tiktok.com/@{username}',
        'Pinterest' : f'https://pinterest.com/{username}',
        'Tumblr'    : f'https://{username}.tumblr.com',
        'Medium'    : f'https://medium.com/@{username}',
        'Dev.to'    : f'https://dev.to/{username}',
        'HackerNews': f'https://news.ycombinator.com/user?id={username}',
        'Pastebin'  : f'https://pastebin.com/u/{username}',
        'GitLab'    : f'https://gitlab.com/{username}',
        'Bitbucket' : f'https://bitbucket.org/{username}',
    }
    output = [f"[*] Social Media Recon: {username!r}\n{'─'*40}"]
    found = []
    for name, url in platforms.items():
        body = _get(url, timeout=4)
        if body and len(body) > 500:
            output.append(f"  [+] {name:<12} → {url}")
            found.append(name)
        else:
            output.append(f"  [ ] {name:<12} → Not found / Private")
    output.append(f"\n[*] Found on {len(found)}/{len(platforms)} platform(s).")
    return '\n'.join(output)


# ── Tech Fingerprint ──────────────────────────────────────────────────────────
def tool_tech_fingerprint(p):
    url = p.get('url', '').strip()
    if not url:
        return "[!] Please provide a URL."
    if not url.startswith('http'):
        url = 'http://' + url
    body = _get(url)
    if not body:
        return f"[!] Could not fetch {url}"
    output = [f"[*] Technology Fingerprint: {url}\n{'─'*40}"]
    checks = {
        'jQuery'        : ['jquery.min.js', 'jquery.js', '/jquery/'],
        'React'         : ['react.min.js', '__NEXT_DATA__', 'react-dom'],
        'Vue.js'        : ['vue.min.js', 'vue.js', '__vue__'],
        'Angular'       : ['angular.js', 'ng-version', 'ng-app'],
        'Bootstrap'     : ['bootstrap.min.css', 'bootstrap.min.js'],
        'Tailwind CSS'  : ['tailwindcss', 'tailwind.min.css'],
        'WordPress'     : ['wp-content', 'wp-includes'],
        'Laravel'       : ['laravel_session', 'csrf_token'],
        'Django'        : ['csrfmiddlewaretoken', 'django'],
        'Ruby on Rails' : ['authenticity_token', 'rails'],
        'PHP'           : ['.php', 'PHP/', 'X-Powered-By: PHP'],
        'ASP.NET'       : ['ASP.NET', '__VIEWSTATE', '.aspx'],
        'Node.js'       : ['X-Powered-By: Express', 'connect.sid'],
        'Apache'        : ['Apache/', 'server: apache'],
        'Nginx'         : ['nginx/', 'server: nginx'],
        'Cloudflare'    : ['cloudflare', '__cfduid', 'cf-ray'],
        'Google Analytics': ['gtag(', 'ga(', 'google-analytics.com'],
        'Font Awesome'  : ['font-awesome', 'fontawesome'],
        'Stripe'        : ['stripe.com/v3', 'Stripe('],
        'reCAPTCHA'     : ['recaptcha', 'www.google.com/recaptcha'],
    }
    found = []
    for tech, patterns in checks.items():
        if any(pat.lower() in body.lower() for pat in patterns):
            found.append(tech)
            output.append(f"  [+] {tech}")
    if not found:
        output.append("  [ ] No specific technologies detected.")
    output.append(f"\n[*] {len(found)} technology/ies identified.")
    return '\n'.join(output)


# ── Domain Age ────────────────────────────────────────────────────────────────
def tool_domain_age(p):
    domain = p.get('domain', '').strip()
    if not domain:
        return "[!] Please provide a domain."
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=15)
        text = result.stdout
        dates = re.findall(r'(?:Creation Date|Created On|Registered On|Domain Registration Date)[:\s]+([^\n\r]+)', text, re.IGNORECASE)
        expiry= re.findall(r'(?:Expir(?:y|ation) Date|Registry Expiry)[:\s]+([^\n\r]+)', text, re.IGNORECASE)
        output = [f"[*] Domain Age: {domain}\n{'─'*40}"]
        if dates:
            output.append(f"  Created  : {dates[0].strip()}")
        if expiry:
            output.append(f"  Expires  : {expiry[0].strip()}")
        if not dates and not expiry:
            output.append("  [!] Could not parse dates from WHOIS.")
            output.append(text[:500])
        return '\n'.join(output)
    except FileNotFoundError:
        return "[!] whois command not found."
    except Exception as e:
        return f"[!] Error: {e}"


# ── ASN Lookup ────────────────────────────────────────────────────────────────
def tool_asn_lookup(p):
    ip = p.get('ip', '').strip()
    if not ip:
        return "[!] Please provide an IP."
    try:
        url = f"https://api.hackertarget.com/aslookup/?q={ip}"
        body = _get(url, timeout=8)
        if body:
            return f"[*] ASN Lookup: {ip}\n{'─'*40}\n{body}"
        # Fallback
        url2 = f"http://ip-api.com/json/{ip}"
        body2 = _get(url2, timeout=8)
        if body2:
            d = json.loads(body2)
            return (f"[*] ASN Lookup: {ip}\n{'─'*40}\n"
                    f"  ASN  : {d.get('as')}\n"
                    f"  ISP  : {d.get('isp')}\n"
                    f"  Org  : {d.get('org')}\n"
                    f"  Country: {d.get('country')}")
        return "[!] ASN lookup failed."
    except Exception as e:
        return f"[!] Error: {e}"
