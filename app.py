from flask import Flask, render_template, jsonify, request, send_from_directory

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

def create_scan_route(service_function, param_extractors):
    """Generic route handler to eliminate duplicate code"""
    def route_handler():
        try:
            data = request.get_json()
            params = {}
            for param_name, extractor in param_extractors.items():
                params[param_name] = extractor(data)
            
            result, status_code = service_function(**params)
            return jsonify(result), status_code
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return route_handler

# =============================================================================
# HIBP (Have I Been Pwned) - Email breach detection
# Cost: $4.50/month for API access
# Focus: Email addresses breach check
# =============================================================================
@app.route('/api/hibp/scan', methods=['POST'])
def hibp_scan_route():
    return create_scan_route(hibp_scan, {'email': lambda d: d.get('email', '').strip()})()

# =============================================================================
# DeHashed - Comprehensive breach detection
# Cost: $21/month + $15/500 credits
# Focus: Email & account breach detection, comprehensive data
# =============================================================================
@app.route('/api/dehashed/scan', methods=['POST'])
def dehashed_scan_route():
    return create_scan_route(dehashed_scan, {
        'email': lambda d: d.get('email', ''),
        'username': lambda d: d.get('username', ''),
        'ip': lambda d: d.get('ip', '')
    })()

# =============================================================================
# LeakCheck - Lightweight breach detection
# Cost: $70/OTP (One-Time Payment)
# Focus: Email addresses, fewer sources, focused approach
# =============================================================================
@app.route('/api/leakcheck/scan', methods=['POST'])
def leakcheck_scan_route():
    return create_scan_route(leakcheck_scan, {'email': lambda d: d.get('email', '').strip()})()

# =============================================================================
# EasyDMARC - Email authentication analysis
# Cost: $36/month
# Focus: Domain email authentication (SPF, DKIM, DMARC records)
# =============================================================================
@app.route('/api/easydmarc/scan', methods=['POST'])
def easydmarc_scan_route():
    return create_scan_route(easydmarc_scan, {'domain': lambda d: d.get('domain', '').strip()})()

# =============================================================================
# Whois API - Domain ownership & DNS information
# Cost: Free (from python whois library)
# Focus: Domain ownership, registrar, nameservers, blacklists
# =============================================================================
@app.route('/api/whois/scan', methods=['POST'])
def whois_scan_route():
    return create_scan_route(whois_scan, {'domain': lambda d: d.get('domain', '').strip()})()

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
    app.run(debug=True, port=8000)
