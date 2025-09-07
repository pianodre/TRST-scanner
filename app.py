from flask import Flask, send_from_directory
import os

# Import our modules
from auth import home_route, login_route, logout_route
from api_routes import (
    hibp_scan_route, dehashed_scan_route, leakcheck_scan_route,
    easydmarc_scan_route, whois_scan_route, dmarc_scan_route, spf_scan_route, combined_scan
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'a8f5f167f44f4964e6c998dee827110c')  # Secure fallback for consumer use

# Authentication routes
@app.route('/')
def home():
    return home_route()

@app.route('/login', methods=['GET', 'POST'])
def login():
    return login_route()

@app.route('/logout')
def logout():
    return logout_route()

# Static file serving
@app.route('/images/<filename>')
def serve_image(filename):
    return send_from_directory('images', filename)

# API routes
@app.route('/api/hibp/scan', methods=['POST'])
def hibp_scan():
    return hibp_scan_route()

@app.route('/api/dehashed/scan', methods=['POST'])
def dehashed_scan():
    return dehashed_scan_route()

@app.route('/api/leakcheck/scan', methods=['POST'])
def leakcheck_scan():
    return leakcheck_scan_route()

@app.route('/api/easydmarc/scan', methods=['POST'])
def easydmarc_scan():
    return easydmarc_scan_route()

@app.route('/api/whois/scan', methods=['POST'])
def whois_scan():
    return whois_scan_route()

@app.route('/api/dmarc/scan', methods=['POST'])
def dmarc_scan():
    return dmarc_scan_route()

@app.route('/api/spf/scan', methods=['POST'])
def spf_scan():
    return spf_scan_route()

@app.route('/api/scan/combined', methods=['POST'])
def combined_scan_endpoint():
    return combined_scan()

if __name__ == '__main__':
    app.run(debug=True, port=8000)
