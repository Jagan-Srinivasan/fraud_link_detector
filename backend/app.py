import os
import requests
import socket
import ssl
import whois
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

VT_API_KEY = os.environ.get("VT_API_KEY")
GSB_API_KEY = os.environ.get("GSB_API_KEY")

# ------------------ CHECK FUNCTIONS ------------------

def simple_check(url):
    suspicious = ["-offer", ".shop", "amaz0n", "flipkarrt", ".xyz", "sale-", "90%off", "promo-"]
    if any(s in url.lower() for s in suspicious):
        return "❌ Fraudulent or Suspicious Link"
    return "✅ Looks Safe"

def virustotal_check(url, basic_result):
    if not VT_API_KEY:
        return "🔄 Not available"

    headers = {"x-apikey": VT_API_KEY}
    scan_url = "https://www.virustotal.com/api/v3/urls"

    try:
        res = requests.post(scan_url, headers=headers, data={"url": url})
        if res.status_code == 200:
            data = res.json()
            url_id = data['data']['id']
            report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            report = requests.get(report_url, headers=headers).json()
            stats = report["data"]["attributes"].get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                return f"❌ VirusTotal: {malicious} malicious"
            elif suspicious > 0:
                return f"⚠️ VirusTotal: {suspicious} suspicious"
            else:
                if "❌" in basic_result:
                    return "⚠️ Clean result ignored due to pattern match"
                return "✅ VirusTotal: Clean"
        return "⚠️ VT API Error"
    except Exception as e:
        print("VT Error:", e)
        return "⚠️ VT Check Failed"

def google_safe_browsing_check(url):
    if not GSB_API_KEY:
        return "🔄 Not available"

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {"clientId": "fraud-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(api_url, json=payload)
        if res.status_code == 200 and "matches" in res.json():
            return "❌ Unsafe (GSB)"
        return "✅ Safe (GSB)"
    except Exception as e:
        print("GSB Error:", e)
        return "⚠️ GSB Error"

def ssl_check(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return "✅ HTTPS Secure"
    except:
        return "❌ No SSL/HTTPS"

def domain_info_check(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        created = w.creation_date if isinstance(w.creation_date, datetime) else w.creation_date[0]
        expires = w.expiration_date if isinstance(w.expiration_date, datetime) else w.expiration_date[0]
        now = datetime.utcnow()

        if created and (now - created).days < 180:
            return f"⚠️ New Domain ({(now - created).days} days old)"
        elif expires and (expires - now).days < 30:
            return "⚠️ Domain expiring soon"
        return "✅ Domain age and expiry look okay"
    except Exception as e:
        print("WHOIS Error:", e)
        return "⚠️ Domain Info Unavailable"

def structure_analysis(url):
    parsed = urlparse(url)
    if len(parsed.path) > 60 or "?" in parsed.query:
        return "⚠️ Long or suspicious structure"
    elif "bit.ly" in url or "tinyurl" in url:
        return "❌ Shortened URL"
    return "✅ Structure normal"

# ------------------ ROUTES ------------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    url = data.get("url", "").strip()
    domain = urlparse(url).netloc

    basic_result = simple_check(url)
    vt_result = virustotal_check(url, basic_result)
    gsb_result = google_safe_browsing_check(url)
    ssl_result = ssl_check(domain)
    whois_result = domain_info_check(url)
    structure_result = structure_analysis(url)

    return jsonify({
        "basic_check": basic_result,
        "vt_check": vt_result,
        "gsb_check": gsb_result,
        "ssl_check": ssl_result,
        "whois_check": whois_result,
        "structure_check": structure_result
    })

# ------------------ MAIN ------------------

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
