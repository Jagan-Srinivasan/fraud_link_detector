import os
import requests
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

# Flask app with correct folder paths
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)  # Allow frontend JS to make POST requests

# Get VirusTotal API key from environment
VT_API_KEY = os.environ.get("VT_API_KEY")

# Simple fraud check logic
def simple_check(url):
    suspicious = ["-offer", ".shop", "amaz0n", "flipkarrt", ".xyz", "sale-"]
    if any(s in url.lower() for s in suspicious):
        return "❌ Fraudulent or Suspicious Link"
    return "✅ Looks Safe"

# VirusTotal URL scan
def virustotal_check(url):
    headers = {
        "x-apikey": VT_API_KEY
    }
    params = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)

    if response.status_code == 200:
        vt_data = response.json()
        analysis_id = vt_data["data"]["id"]

        # Get analysis result
        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        if analysis_response.status_code == 200:
            result = analysis_response.json()
            stats = result["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0 or suspicious > 0:
                return f"❌ VirusTotal: {malicious} malicious, {suspicious} suspicious"
            else:
                return "✅ VirusTotal: Clean"
        else:
            return "⚠️ VirusTotal scan result pending"
    else:
        return "⚠️ VirusTotal API error"

# Home page
@app.route('/')
def home():
    return render_template('index.html')

# API route
@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    url = data.get('url')
    basic_result = simple_check(url)
    vt_result = virustotal_check(url) if VT_API_KEY else "⚠️ VirusTotal API Key Not Set"
    
    return jsonify({
        "basic_check": basic_result,
        "vt_check": vt_result
    })

# Run server
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
