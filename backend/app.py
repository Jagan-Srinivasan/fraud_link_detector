import os
from flask import Flask, request, jsonify, render_template

app = Flask(__name__, template_folder="templates", static_folder="static")


# Basic fraud check function
def simple_check(url):
    suspicious = ["-offer", ".shop", "amaz0n", "flipkarrt", ".xyz", "sale-"]
    if any(s in url.lower() for s in suspicious):
        return "❌ Fraudulent or Suspicious Link"
    return "✅ Looks Safe"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    url = data.get('url')
    result = simple_check(url)
    return jsonify({"result": result})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000)

