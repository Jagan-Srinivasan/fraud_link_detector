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
    url = data.get('url', '')

    # Step 1: Basic check
    basic_result = simple_check(url)

    # Step 2: VirusTotal Check (only if API key is set)
    vt_api_key = os.getenv("VT_API_KEY")
    vt_status = "🔄 Not available"

    if vt_api_key:
        import requests
        headers = {"x-apikey": vt_api_key}
        scan_url = "https://www.virustotal.com/api/v3/urls"
        try:
            # Encode URL
            res = requests.post(scan_url, headers=headers, data={"url": url})
            if res.status_code == 200:
                data = res.json()
                url_id = data['data']['id']

                # Fetch scan report
                report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
                report = requests.get(report_url, headers=headers).json()
                stats = report["data"]["attributes"].get("stats", {})
                if stats.get("malicious", 0) > 0:
                    vt_status = "❌ VirusTotal: Malicious"
                elif stats.get("suspicious", 0) > 0:
                    vt_status = "⚠️ VirusTotal: Suspicious"
                else:
                    vt_status = "✅ VirusTotal: Clean"
            else:
                vt_status = "⚠️ VT API Error"
        except Exception as e:
            print("VirusTotal Error:", e)
            vt_status = "⚠️ VT Check Failed"

    # Send both results clearly
    return jsonify({
        "basic_check": basic_result,
        "vt_check": vt_status
    })


# Run server
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
