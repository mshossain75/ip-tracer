from flask import Flask, request, render_template
import ipaddress
import socket
import requests
import whois

app = Flask(__name__)

def is_public_ip(ip):
    return not ipaddress.ip_address(ip).is_private

def get_geolocation(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return res
    except:
        return {}

@app.route("/")
def home():
    return render_template("landing.html")

@app.route("/ip-tracer", methods=["GET", "POST"])
def trace():
    info = {}
    if request.method == "POST":
        ip = request.form["ip"]
        info["ip"] = ip
        info["is_public"] = is_public_ip(ip)
        info["geo"] = get_geolocation(ip)
        try:
            info["whois"] = whois.whois(ip)
        except:
            info["whois"] = "Error fetching WHOIS"
        try:
            info["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except:
            info["reverse_dns"] = "N/A"
    return render_template("index.html", info=info)

# ✅ THIS IS THE FIX FOR RENDER
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
