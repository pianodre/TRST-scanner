from flask import Flask, render_template, jsonify, request, send_from_directory
import requests
import os

from services.domain_services import whois_scan, easydmarc_scan
from services.email_services import leakcheck_scan, hibp_scan, dehashed_scan
from services.security_utils import assess_combined_risk, format_security_message

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/images/<filename>')
def serve_image(filename):
    return send_from_directory('images', filename)

# =============================================================================
# HIBP (Have I Been Pwned) - Email breach detection
# Cost: $4.50/month for API access
# Focus: Email addresses breach check
# =============================================================================
@app.route('/api/hibp/scan', methods=['POST'])
def hibp_scan_route():
    """Route for HIBP email breach detection"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        
        result, status_code = hibp_scan(email)
        return jsonify(result), status_code
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# DeHashed - Comprehensive breach detection
# Cost: $21/month + $15/500 credits
# Focus: Email & account breach detection, comprehensive data
# =============================================================================
@app.route('/api/dehashed/scan', methods=['POST'])
def dehashed_scan_route():
    """Route for DeHashed breach detection"""
    try:
        data = request.get_json()
        email = data.get('email', '')
        username = data.get('username', '')
        ip = data.get('ip', '')
        
        result, status_code = dehashed_scan(email, username, ip)
        return jsonify(result), status_code
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# LeakCheck - Lightweight breach detection
# Cost: $70/OTP (One-Time Payment)
# Focus: Email addresses, fewer sources, focused approach
# =============================================================================
@app.route('/api/leakcheck/scan', methods=['POST'])
def leakcheck_scan_route():
    """Route for LeakCheck email breach detection"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        
        result, status_code = leakcheck_scan(email)
        return jsonify(result), status_code
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# EasyDMARC - Email authentication analysis
# Cost: $36/month
# Focus: Domain email authentication (SPF, DKIM, DMARC records)
# =============================================================================
@app.route('/api/easydmarc/scan', methods=['POST'])
def easydmarc_scan_route():
    """Route for EasyDMARC domain analysis"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        result, status_code = easydmarc_scan(domain)
        return jsonify(result), status_code
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# Whois API - Domain ownership & DNS information
# Cost: Free (from python whois library)
# Focus: Domain ownership, registrar, nameservers, blacklists
# =============================================================================
@app.route('/api/whois/scan', methods=['POST'])
def whois_scan_route():
    """Route for WHOIS domain analysis"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        result, status_code = whois_scan(domain)
        return jsonify(result), status_code
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# Combined scan endpoint - orchestrates multiple services
# =============================================================================
@app.route('/api/scan/combined', methods=['POST'])
def combined_scan():
    """
    Combined scanning using multiple services
    - Orchestrates calls to different APIs based on scan type
    - Aggregates results from multiple sources
    - Provides comprehensive security assessment
    """
    try:
        data = request.get_json()
        scan_type = data.get('type', 'domain')
        domain = data.get('domain', '').strip()
        email = data.get('email', '').strip()
        
        domain_data = None
        email_data = None
        
        # Perform domain scans
        if scan_type in ['domain', 'both'] and domain:
            domain_result, _ = whois_scan(domain)
            if domain_result.get('status') == 'success':
                domain_data = domain_result
        
        # Perform email scans
        if scan_type in ['email', 'both'] and email:
            email_result, _ = leakcheck_scan(email)
            if email_result.get('status') == 'success':
                email_data = email_result
        
        # Generate combined security assessment
        security_assessment = assess_combined_risk(domain_data, email_data)
        
        results = {
            'scan_type': scan_type,
            'domain': domain,
            'email': email,
            'domain_data': domain_data,
            'email_data': email_data,
            'security_assessment': security_assessment,
            'message': format_security_message(
                security_assessment['overall_risk'], 
                security_assessment['risk_factors']
            )
        }
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8001)
