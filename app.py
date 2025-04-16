from flask import Flask, request, render_template
import ipaddress
import socket
import requests
import whois
import argparse
import subprocess
import re

app = Flask(__name__)

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def geolocate_ip(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return r.json()
    except:
        return {}

def whois_lookup(ip):
    try:
        output = subprocess.check_output(['whois', ip], text=True)
        info = {}
        for line in output.splitlines():
            if ':' in line:
                key, val = line.split(':', 1)
                key = key.strip().lower()
                val = val.strip()
                if any(k in key for k in ['orgname', 'organisation', 'abuse', 'admin', 'tech', 'email']):
                    info[key] = val
        return info
    except:
        return {}

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "No PTR record"

def check_blacklist(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': 'd00da4abb8e83e9181e591b487bd51ffb465807c0bceef29b407143495e69eaa15ae55f40b34288c',  # Replace with your real key
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        r = requests.get(url, headers=headers, params=params)
        return r.json().get("data", {})
    except:
        return {}

def shodan_lookup(ip):
    try:
        SHODAN_API_KEY = "d7XPNRz9bR3NDW81NxI0U2MHmbKQqYLr"  # Replace
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}")
        return r.json()
    except:
        return {}

def port_scan(ip):
    try:
        result = subprocess.check_output(["nmap", "-F", ip], stderr=subprocess.DEVNULL, text=True)
        return result
    except:
        return "Port scan failed."

def main():
    parser = argparse.ArgumentParser(description="IP OSINT Toolkit")
    parser.add_argument("ip", help="Target IP Address")
    args = parser.parse_args()
    ip = args.ip

    print(f"\n🔎 IP: {ip}")
    print("--------------------------------------------------")

    if is_private_ip(ip):
        print("🔒 This is a **Private IP Address**.\n")
        return

    print("🌍 Public IP Detected. Running OSINT...\n")

    # Reverse DNS
    print(f"📡 Reverse DNS: {reverse_dns(ip)}")

    # Geolocation
    geo = geolocate_ip(ip)
    if geo:
        print("\n📍 Geolocation Info (via ipinfo.io):")
        for k in ['ip', 'city', 'region', 'country', 'loc', 'org', 'timezone']:
            if geo.get(k):
                print(f"  {k.capitalize():12}: {geo[k]}")

    # WHOIS
    whois = whois_lookup(ip)
    if whois:
        print("\n📬 WHOIS Contact Info:")
        for k, v in whois.items():
            print(f"  {k.capitalize():15}: {v}")

    # AbuseIPDB Check
    abuse = check_blacklist(ip)
    if abuse:
        print("\n🚨 Reputation (via AbuseIPDB):")
        print(f"  ISP             : {abuse.get('isp')}")
        print(f"  Domain          : {abuse.get('domain')}")
        print(f"  Total Reports   : {abuse.get('totalReports')}")
        print(f"  Abuse Score     : {abuse.get('abuseConfidenceScore')}%")
        print(f"  Last Reported   : {abuse.get('lastReportedAt')}")

    # Shodan Lookup
    shodan = shodan_lookup(ip)
    if shodan and isinstance(shodan, dict) and shodan.get("ports"):
        print("\n🛡️ Shodan Data:")
        print(f"  Hostnames       : {shodan.get('hostnames')}")
        print(f"  Open Ports      : {shodan.get('ports')}")
        for service in shodan.get("data", []):
            print(f"  - Port {service.get('port')}: {service.get('product', '')} {service.get('version', '')}")

    # Fast Port Scan
    print("\n🧪 Running Quick Nmap Port Scan:")
    print(port_scan(ip))

    print("--------------------------------------------------")
    print("✅ OSINT Complete.\n")

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)


