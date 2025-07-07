import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

# Flask app with correct folder paths
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)  # Allow frontend JS to make POST requests

# Simple fraud check logic
def simple_check(url):
    suspicious = ["-offer", ".shop", "amaz0n", "flipkarrt", ".xyz", "sale-"]
    if any(s in url.lower() for s in suspicious):
        return "❌ Fraudulent or Suspicious Link"
    return "✅ Looks Safe"

# Home page
@app.route('/')
def home():
    return render_template('index.html')

# API route
@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    print("Received data:", data)  # For debugging
    url = data.get('url')
    result = simple_check(url)
    return jsonify({"result": result})

# Run server (locally: 5000, on Render: auto port)
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
