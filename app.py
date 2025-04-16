from flask import Flask, request, render_template
import ipaddress
import socket
import requests
import subprocess

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
        SHODAN_API_KEY = "d7XPNRz9bR3NDW81NxI0U2MHmbKQqYLr"  # Replace with your real key
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

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        ip = request.form.get("ip")
        if not ip:
            return render_template("index.html", error="Please enter an IP address.")

        result = {}
        result["ip"] = ip
        result["is_private"] = is_private_ip(ip)

        if not result["is_private"]:
            result["reverse_dns"] = reverse_dns(ip)
            result["geo"] = geolocate_ip(ip)
            result["whois"] = whois_lookup(ip)
            result["blacklist"] = check_blacklist(ip)
            result["shodan"] = shodan_lookup(ip)
            result["nmap"] = port_scan(ip)
        return render_template("index.html", result=result)

    return render_template("index.html")

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
