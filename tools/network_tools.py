import socket
import subprocess
import ipaddress
import struct
import json
import urllib.request
import urllib.error
import time
import re

# ── Port Scanner ──────────────────────────────────────────────────────────────
def tool_port_scanner(p):
    host = p.get('host', '').strip()
    ports_input = p.get('ports', '1-1024').strip()
    timeout = float(p.get('timeout', 0.5))

    if not host:
        return "[!] Please provide a host."

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return f"[!] Cannot resolve host: {host}"

    # Parse port range
    open_ports = []
    try:
        if '-' in ports_input:
            start, end = ports_input.split('-')
            port_list = range(int(start), int(end) + 1)
        elif ',' in ports_input:
            port_list = [int(x) for x in ports_input.split(',')]
        else:
            port_list = range(1, int(ports_input) + 1)
    except:
        port_list = range(1, 1025)

    port_list = list(port_list)[:500]   # cap to 500

    output = [f"[*] Scanning {host} ({ip})\n[*] Ports: {ports_input}\n{'─'*40}"]

    COMMON_SERVICES = {
        21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
        80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
        3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL', 6379:'Redis',
        8080:'HTTP-Alt', 8443:'HTTPS-Alt', 27017:'MongoDB'
    }

    for port in port_list:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                svc = COMMON_SERVICES.get(port, 'unknown')
                open_ports.append(port)
                output.append(f"  [+] {port:5d}/tcp  OPEN   {svc}")
        except:
            pass

    output.append(f"\n{'─'*40}")
    output.append(f"[*] Scan complete. {len(open_ports)} open port(s) found.")
    return '\n'.join(output)


# ── Ping ──────────────────────────────────────────────────────────────────────
def tool_ping(p):
    host = p.get('host', '').strip()
    count = int(p.get('count', 4))
    if not host:
        return "[!] Please provide a host."
    count = min(count, 10)
    try:
        result = subprocess.run(
            ['ping', '-c', str(count), host],
            capture_output=True, text=True, timeout=20
        )
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return "[!] Ping timed out."
    except Exception as e:
        return f"[!] Error: {e}"


# ── Traceroute ────────────────────────────────────────────────────────────────
def tool_traceroute(p):
    host = p.get('host', '').strip()
    if not host:
        return "[!] Please provide a host."
    try:
        result = subprocess.run(
            ['traceroute', '-m', '20', host],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout or result.stderr or "[!] traceroute returned no output."
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ['tracepath', host],
                capture_output=True, text=True, timeout=60
            )
            return result.stdout or result.stderr
        except:
            return "[!] traceroute/tracepath not available."
    except Exception as e:
        return f"[!] Error: {e}"


# ── DNS Lookup ────────────────────────────────────────────────────────────────
def tool_dns_lookup(p):
    domain = p.get('domain', '').strip()
    if not domain:
        return "[!] Please provide a domain."
    output = [f"[*] DNS Lookup: {domain}\n{'─'*40}"]
    try:
        ip = socket.gethostbyname(domain)
        output.append(f"  A Record   : {ip}")
    except:
        output.append(f"  [!] Cannot resolve {domain}")
    try:
        results = socket.getaddrinfo(domain, None)
        ipv6_set = set()
        for r in results:
            if r[0] == socket.AF_INET6:
                ipv6_set.add(r[4][0])
        for v6 in ipv6_set:
            output.append(f"  AAAA Record: {v6}")
    except:
        pass
    try:
        fqdn = socket.getfqdn(domain)
        output.append(f"  FQDN       : {fqdn}")
    except:
        pass
    output.append(f"\n[*] Lookup complete.")
    return '\n'.join(output)


# ── Reverse DNS ───────────────────────────────────────────────────────────────
def tool_reverse_dns(p):
    ip = p.get('ip', '').strip()
    if not ip:
        return "[!] Please provide an IP."
    try:
        hostname = socket.gethostbyaddr(ip)
        return f"[*] Reverse DNS for {ip}\n{'─'*40}\n  Hostname: {hostname[0]}\n  Aliases : {', '.join(hostname[1]) or 'none'}"
    except socket.herror as e:
        return f"[!] No reverse DNS record found for {ip}. ({e})"
    except Exception as e:
        return f"[!] Error: {e}"


# ── WHOIS ─────────────────────────────────────────────────────────────────────
def tool_whois(p):
    domain = p.get('domain', '').strip()
    if not domain:
        return "[!] Please provide a domain."
    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True, text=True, timeout=20
        )
        out = result.stdout[:3000] if result.stdout else result.stderr
        return f"[*] WHOIS: {domain}\n{'─'*40}\n{out}"
    except FileNotFoundError:
        return "[!] whois command not found on this system."
    except Exception as e:
        return f"[!] Error: {e}"


# ── ARP Scan ──────────────────────────────────────────────────────────────────
def tool_arp_scan(p):
    interface = p.get('interface', 'eth0').strip()
    try:
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True, text=True, timeout=10
        )
        out = result.stdout or "[!] ARP table empty or permission denied."
        return f"[*] ARP Cache (Local Network)\n{'─'*40}\n{out}"
    except Exception as e:
        return f"[!] Error: {e}"


# ── Banner Grabber ────────────────────────────────────────────────────────────
def tool_banner_grab(p):
    host = p.get('host', '').strip()
    port = int(p.get('port', 80))
    if not host:
        return "[!] Please provide a host."
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(1024).decode(errors='ignore')
        s.close()
        return f"[*] Banner from {host}:{port}\n{'─'*40}\n{banner}"
    except Exception as e:
        return f"[!] Could not grab banner: {e}"


# ── Network Range Scan ────────────────────────────────────────────────────────
def tool_network_range_scan(p):
    cidr = p.get('cidr', '').strip()
    if not cidr:
        return "[!] Please provide a CIDR range (e.g. 192.168.1.0/24)."
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        hosts = list(network.hosts())[:50]
        output = [f"[*] Scanning {cidr} ({len(list(network.hosts()))} hosts, checking first 50)\n{'─'*40}"]
        alive = []
        for host in hosts:
            ip_str = str(host)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((ip_str, 80))
                s.close()
                if result == 0:
                    alive.append(ip_str)
                    output.append(f"  [+] {ip_str}  ALIVE (port 80 open)")
            except:
                pass
        output.append(f"\n[*] Done. {len(alive)} host(s) responded.")
        return '\n'.join(output)
    except ValueError as e:
        return f"[!] Invalid CIDR: {e}"


# ── Open Port Finder ──────────────────────────────────────────────────────────
def tool_open_port_finder(p):
    host = p.get('host', '').strip()
    if not host:
        return "[!] Please provide a host."
    COMMON = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,27017]
    output = [f"[*] Common Port Check: {host}\n{'─'*40}"]
    for port in COMMON:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            r = s.connect_ex((host, port))
            s.close()
            status = "OPEN  ✔" if r == 0 else "closed"
            output.append(f"  {port:5d}/tcp  {status}")
        except:
            pass
    return '\n'.join(output)


# ── TCP Connect Test ──────────────────────────────────────────────────────────
def tool_tcp_connect(p):
    host = p.get('host', '').strip()
    port = int(p.get('port', 80))
    if not host:
        return "[!] Please provide a host."
    try:
        start = time.time()
        s = socket.socket()
        s.settimeout(5)
        r = s.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000
        s.close()
        if r == 0:
            return f"[+] TCP Connection SUCCESS\n    Host   : {host}\n    Port   : {port}\n    Latency: {elapsed:.2f} ms"
        else:
            return f"[-] TCP Connection FAILED\n    Host : {host}\n    Port : {port}\n    Code : {r}"
    except Exception as e:
        return f"[!] Error: {e}"


# ── UDP Scan ──────────────────────────────────────────────────────────────────
def tool_udp_scan(p):
    host = p.get('host', '').strip()
    port = int(p.get('port', 53))
    if not host:
        return "[!] Please provide a host."
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(b'\x00', (host, port))
        try:
            data, _ = s.recvfrom(1024)
            return f"[+] UDP {host}:{port} → OPEN (received {len(data)} bytes)"
        except socket.timeout:
            return f"[?] UDP {host}:{port} → OPEN|FILTERED (no response)"
    except Exception as e:
        return f"[!] Error: {e}"
    finally:
        s.close()


# ── MAC Lookup ────────────────────────────────────────────────────────────────
def tool_mac_lookup(p):
    mac = p.get('mac', '').strip().replace('-', ':').upper()
    if not mac:
        return "[!] Please provide a MAC address."
    prefix = mac[:8].replace(':', '')
    try:
        url = f"https://api.macvendors.com/{urllib.parse.quote(mac)}"
        req = urllib.request.Request(url, headers={'User-Agent': 'CyberKit/1.0'})
        with urllib.request.urlopen(req, timeout=5) as r:
            vendor = r.read().decode()
        return f"[*] MAC Lookup: {mac}\n{'─'*40}\n  Vendor: {vendor}"
    except Exception as e:
        return f"[!] MAC lookup failed (may need internet): {e}"


# ── IP Geolocation ────────────────────────────────────────────────────────────
def tool_ip_geolocation(p):
    ip = p.get('ip', '').strip()
    if not ip:
        return "[!] Please provide an IP address."
    try:
        url = f"http://ip-api.com/json/{ip}"
        req = urllib.request.Request(url, headers={'User-Agent': 'CyberKit/1.0'})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
        if data.get('status') == 'success':
            return (f"[*] GeoIP: {ip}\n{'─'*40}\n"
                    f"  Country : {data.get('country')}\n"
                    f"  Region  : {data.get('regionName')}\n"
                    f"  City    : {data.get('city')}\n"
                    f"  ZIP     : {data.get('zip')}\n"
                    f"  ISP     : {data.get('isp')}\n"
                    f"  Org     : {data.get('org')}\n"
                    f"  ASN     : {data.get('as')}\n"
                    f"  Lat/Lon : {data.get('lat')}, {data.get('lon')}")
        else:
            return f"[!] GeoIP lookup failed: {data.get('message', 'unknown error')}"
    except Exception as e:
        return f"[!] Error: {e}"


# ── Subnet Calculator ─────────────────────────────────────────────────────────
def tool_subnet_calc(p):
    cidr = p.get('cidr', '').strip()
    if not cidr:
        return "[!] Please provide CIDR notation (e.g. 192.168.1.0/24)."
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        return (f"[*] Subnet Calculator: {cidr}\n{'─'*40}\n"
                f"  Network    : {net.network_address}\n"
                f"  Broadcast  : {net.broadcast_address}\n"
                f"  Netmask    : {net.netmask}\n"
                f"  Wildcard   : {net.hostmask}\n"
                f"  Hosts      : {net.num_addresses - 2:,}\n"
                f"  Prefix     : /{net.prefixlen}\n"
                f"  First Host : {list(net.hosts())[0] if net.num_addresses > 2 else 'N/A'}\n"
                f"  Last Host  : {list(net.hosts())[-1] if net.num_addresses > 2 else 'N/A'}")
    except ValueError as e:
        return f"[!] Invalid CIDR: {e}"
