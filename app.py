#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║          CYBERKIT - Professional Hacker Toolkit       ║
║              Dual Server: Local + Public IP           ║
╚═══════════════════════════════════════════════════════╝
"""

import os
import sys
import socket
import threading
import subprocess
import ipaddress
import json
import re
import time
import hashlib
import base64
import urllib.parse
import urllib.request
import struct
import random
import string
import ssl
import http.client
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
from tools.network_tools import *
from tools.web_tools import *
from tools.crypto_tools import *
from tools.system_tools import *
from tools.recon_tools import *

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/tool', methods=['POST'])
def run_tool():
    data = request.get_json()
    tool_name = data.get('tool')
    params = data.get('params', {})
    try:
        result = dispatch_tool(tool_name, params)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'result': f'[ERROR] {str(e)}'})

@app.route('/api/status')
def server_status():
    return jsonify({
        'status': 'online',
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'hostname': socket.gethostname(),
        'ip': get_local_ip()
    })

# ─────────────────────────────────────────────
#  TOOL DISPATCHER
# ─────────────────────────────────────────────

def dispatch_tool(name, params):
    tools = {
        # Network Tools
        'port_scanner':        tool_port_scanner,
        'ping_host':           tool_ping,
        'traceroute':          tool_traceroute,
        'dns_lookup':          tool_dns_lookup,
        'reverse_dns':         tool_reverse_dns,
        'whois_lookup':        tool_whois,
        'arp_scan':            tool_arp_scan,
        'banner_grabber':      tool_banner_grab,
        'network_range_scan':  tool_network_range_scan,
        'open_port_finder':    tool_open_port_finder,
        'tcp_connect_test':    tool_tcp_connect,
        'udp_scan':            tool_udp_scan,
        'mac_lookup':          tool_mac_lookup,
        'ip_geolocation':      tool_ip_geolocation,
        'subnet_calculator':   tool_subnet_calc,

        # Web Tools
        'http_headers':        tool_http_headers,
        'robots_txt':          tool_robots_txt,
        'sitemap_finder':      tool_sitemap,
        'dir_bruteforce':      tool_dir_bruteforce,
        'sql_injection_test':  tool_sqli_test,
        'xss_scanner':         tool_xss_scan,
        'ssl_checker':         tool_ssl_check,
        'url_encoder':         tool_url_encode,
        'url_decoder':         tool_url_decode,
        'http_method_test':    tool_http_methods,
        'cookie_analyzer':     tool_cookie_analyzer,
        'web_crawler':         tool_web_crawler,
        'cms_detector':        tool_cms_detect,
        'email_harvester':     tool_email_harvest,
        'wayback_lookup':      tool_wayback,

        # Crypto Tools
        'md5_hash':            tool_md5,
        'sha1_hash':           tool_sha1,
        'sha256_hash':         tool_sha256,
        'sha512_hash':         tool_sha512,
        'base64_encode':       tool_base64_encode,
        'base64_decode':       tool_base64_decode,
        'caesar_cipher':       tool_caesar,
        'rot13':               tool_rot13,
        'hex_encode':          tool_hex_encode,
        'hex_decode':          tool_hex_decode,
        'jwt_decoder':         tool_jwt_decode,
        'password_strength':   tool_pass_strength,
        'password_generator':  tool_pass_gen,
        'hash_cracker':        tool_hash_crack,
        'xor_cipher':          tool_xor_cipher,

        # System Tools
        'system_info':         tool_sys_info,
        'process_list':        tool_process_list,
        'disk_usage':          tool_disk_usage,
        'network_interfaces':  tool_net_interfaces,
        'env_variables':       tool_env_vars,
        'file_hash_check':     tool_file_hash,
        'log_analyzer':        tool_log_analyze,
        'firewall_rules':      tool_firewall_check,

        # Recon Tools
        'google_dork':         tool_google_dork,
        'social_recon':        tool_social_recon,
        'tech_fingerprint':    tool_tech_fingerprint,
        'domain_age':          tool_domain_age,
        'asn_lookup':          tool_asn_lookup,
    }

    fn = tools.get(name)
    if not fn:
        return f"[!] Unknown tool: {name}"
    return fn(params)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


# ─────────────────────────────────────────────
#  DUAL SERVER LAUNCHER
# ─────────────────────────────────────────────

def run_server(host, port, label):
    print(f"\n  ┌─ {label}")
    print(f"  └─► http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    PUBLIC_IP = get_local_ip()

    print("""
               _____ ___  _ ____  ____
              /__ __/  \///  __\/  _ /
                / \   \  / |  \/|| / \|
                | |   / /  |    /| |-||
                \_/  /_/   \_/\_//_/ \|
  ║            PROFESSIONAL HACKER TOOLKIT          ║
    """)

    # Thread 1 – Localhost
    t1 = threading.Thread(
        target=run_server, args=('127.0.0.1', 5000, 'Localhost Server'),
        daemon=True
    )
    # Thread 2 – Public/LAN IP
    t2 = threading.Thread(
        target=run_server, args=(PUBLIC_IP, 8080, f'Network Server ({PUBLIC_IP})'),
        daemon=True
    )

    t1.start()
    time.sleep(0.5)
    t2.start()

    print(f"""
  ╔══════════════════════════════════════════════════╗
  ║  SERVERS RUNNING                                 ║
  ║  Localhost  ► http://127.0.0.1:5000              ║
  ║  Network    ► http://{PUBLIC_IP}:8080{'':>{20-len(PUBLIC_IP)}}║
  ╚══════════════════════════════════════════════════╝
  Press Ctrl+C to stop.
    """)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  [!] Shutting down CyberKit...")
        sys.exit(0)
