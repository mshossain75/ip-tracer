from flask import Flask, request, jsonify
import ipaddress
import socket
import requests
import subprocess

app = Flask(__name__)

# Helper Functions
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
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': 'd00da4abb8e83e9181e591b487bd51ffb465807c0bceef29b407143495e69eaa15ae55f40b34288c',  # Replace with real key
            'Accept': 'application/json'
        }
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        r = requests.get(url, headers=headers, params=params)
        return r.json().get("data", {})
    except:
        return {}

def shodan_lookup(ip):
    try:
        SHODAN_API_KEY = "d7XPNRz9bR3NDW81NxI0U2MHmbKQqYLr"  # Replace with real key
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

# Routes
@app.route('/')
def home():
    return "🛡️ IP OSINT Toolkit API is Running"

@app.route('/api/check-ip')
def check_ip():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "IP address is required."}), 400

    return jsonify({
        "ip": ip,
        "is_private": is_private_ip(ip)
    })

@app.route('/api/geolocation')
def api_geolocation():
    ip = request.args.get("ip")
    return jsonify(geolocate_ip(ip))

@app.route('/api/whois')
def api_whois():
    ip = request.args.get("ip")
    return jsonify(whois_lookup(ip))

@app.route('/api/reverse-dns')
def api_reverse_dns():
    ip = request.args.get("ip")
    return jsonify({"ip": ip, "ptr_record": reverse_dns(ip)})

@app.route('/api/blacklist')
def api_blacklist():
    ip = request.args.get("ip")
    return jsonify(check_blacklist(ip))

@app.route('/api/shodan')
def api_shodan():
    ip = request.args.get("ip")
    return jsonify(shodan_lookup(ip))

@app.route('/api/port-scan')
def api_port_scan():
    ip = request.args.get("ip")
    return jsonify({"result": port_scan(ip)})

@app.route('/api/full-osint')
def full_osint():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "IP address is required."}), 400

    if is_private_ip(ip):
        return jsonify({"ip": ip, "note": "Private IP - OSINT not performed."})

    return jsonify({
        "ip": ip,
        "reverse_dns": reverse_dns(ip),
        "geolocation": geolocate_ip(ip),
        "whois": whois_lookup(ip),
        "blacklist": check_blacklist(ip),
        "shodan": shodan_lookup(ip),
        "port_scan": port_scan(ip)
    })

# Run Server
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
