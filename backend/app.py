import os
import requests
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# ENV VARS
VT_API_KEY = os.environ.get("VT_API_KEY")
GSB_API_KEY = os.environ.get("GSB_API_KEY")

# ------------------ CHECK FUNCTIONS ------------------

def simple_check(url):
    suspicious = ["-offer", ".shop", "amaz0n", "flipkarrt", ".xyz", "sale-"]
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
        else:
            return "⚠️ VT API Error"
    except Exception as e:
        print("VirusTotal Error:", e)
        return "⚠️ VT Check Failed"

def google_safe_browsing_check(url):
    if not GSB_API_KEY:
        return "🔄 Not available"
    
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {
            "clientId": "fraud-link-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        res = requests.post(api_url, json=payload)
        data = res.json()
        if "matches" in data:
            return "❌ Unsafe (Google Safe Browsing)"
        return "✅ Safe (GSB)"
    except Exception as e:
        print("GSB Error:", e)
        return "⚠️ GSB Error"

# ------------------ ROUTES ------------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    url = data.get('url', '').strip()
    print("Received URL:", url)

    basic_result = simple_check(url)
    vt_result = virustotal_check(url, basic_result)
    gsb_result = google_safe_browsing_check(url)

    return jsonify({
        "basic_check": basic_result,
        "vt_check": vt_result,
        "gsb_check": gsb_result
    })

# ------------------ RUN ------------------

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
