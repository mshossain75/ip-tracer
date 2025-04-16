from flask import Flask, request, render_template
import ipaddress
import socket
import requests
import subprocess
import os
import shutil

from dotenv import load_dotenv
from flask import make_response
from xhtml2pdf import pisa
from io import BytesIO


load_dotenv()

app = Flask(__name__)

# Load API keys from environment variables
IPINFO_TOKEN = os.getenv("92fad0c184571d")
ABUSEIPDB_KEY = os.getenv("d00da4abb8e83e9181e591b487bd51ffb465807c0bceef29b407143495e69eaa15ae55f40b34288c")
SHODAN_API_KEY = os.getenv("d7XPNRz9bR3NDW81NxI0U2MHmbKQqYLr")
VIEWDNS_KEY = os.getenv("b01124d6abbaf4956d44412d6512f7ece2e687d1")
IPQS_KEY = os.getenv("bAe76K0k9YYnphSZHnE13zzLNa896zwu")

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def geolocate_ip(ip):
    try:
        headers = {"Authorization": f"Bearer {IPINFO_TOKEN}"}
        r = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=5)
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
            'Key': ABUSEIPDB_KEY,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        r = requests.get(url, headers=headers, params=params, timeout=10)
        return r.json().get("data", {})
    except:
        return {}

def shodan_lookup(ip):
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=10)
        return r.json()
    except:
        return {}

def viewdns_port_scan(ip):
    try:
        key = os.getenv("VIEWDNS_KEY")
        url = f"https://api.viewdns.info/portscan/?host={ip}&apikey={key}&output=json"
        r = requests.get(url, timeout=10)
        data = r.json()

        ports = data.get("response", {}).get("port", [])
        return [f"{p['number']}/tcp - {p['status']}" for p in ports] if ports else ["No open ports found."]
    except:
        return ["ViewDNS Port Scan failed."]

def viewdns_reverse_ip(ip):
    try:
        key = os.getenv("VIEWDNS_KEY")
        url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey={key}&output=json"
        r = requests.get(url, timeout=10)
        return r.json().get("response", {}).get("domains", [])
    except:
        return []

def viewdns_http_headers(ip):
    try:
        key = os.getenv("VIEWDNS_KEY")
        url = f"https://api.viewdns.info/httpheaders/?url={ip}&apikey={key}&output=json"
        r = requests.get(url, timeout=10)
        return r.json().get("response", {}).get("headers", {})
    except:
        return {}

def viewdns_dns_records(ip):
    try:
        key = os.getenv("VIEWDNS_KEY")
        url = f"https://api.viewdns.info/dnsrecord/?domain={ip}&apikey={key}&output=json"
        r = requests.get(url, timeout=10)
        return r.json().get("response", {}).get("records", [])
    except:
        return []

def ipqs_lookup(ip):
    try:
        key = os.getenv("IPQS_API_KEY")
        url = f"https://ipqualityscore.com/api/json/ip/{key}/{ip}"
        r = requests.get(url, timeout=10)
        return r.json()
    except:
        return {}


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
            result["viewdns_reverse_ip"] = viewdns_reverse_ip(ip)
            result["viewdns_port_scan"] = viewdns_port_scan(ip)
            result["viewdns_http_headers"] = viewdns_http_headers(ip)
            result["viewdns_dns_records"] = viewdns_dns_records(ip)
            result["ipqs_lookup"] = ipqs_lookup(ip)

	
        return render_template("index.html", result=result)

    return render_template("index.html")

@app.route("/download", methods=["POST"])
def download_pdf():
    ip = request.form.get("ip")
    if not ip or not is_valid_ip(ip):
        return render_template("index.html", error="Invalid IP for PDF download.")

    result = {
        "ip": ip,
        "is_private": is_private_ip(ip)
    }

    if not result["is_private"]:
        result["reverse_dns"] = reverse_dns(ip)
        result["geo"] = geolocate_ip(ip)
        result["whois"] = whois_lookup(ip)
        result["blacklist"] = check_blacklist(ip)
        result["shodan"] = shodan_lookup(ip)
        result["viewdns_reverse_ip"] = viewdns_reverse_ip(ip)
        result["viewdns_port_scan"] = viewdns_port_scan(ip)
        result["viewdns_http_headers"] = viewdns_http_headers(ip)
        result["viewdns_dns_records"] = viewdns_dns_records(ip)
        result["ipqs_lookup"] = ipqs_lookup(ip)

    # Render HTML from template
    html = render_template("pdf_template.html", result=result)
    pdf_stream = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf_stream)

    if pisa_status.err:
        return "PDF generation failed", 500

    response = make_response(pdf_stream.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=IP_Report_{ip}.pdf"
    return response

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
