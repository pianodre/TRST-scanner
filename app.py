from flask import Flask, render_template, jsonify, request, send_from_directory
import requests
import os

import whois

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
def hibp_scan():
    """
    Have I Been Pwned API integration
    - Email breach detection
    - Quick email breach check
    - Limited sources, mostly major breaches
    """
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        
        # TODO: Implement HIBP API integration
        # API endpoint: https://haveibeenpwned.com/api/v3/breachedaccount/{email}
        # Requires API key and User-Agent header
        
        return jsonify({
            'status': 'template',
            'service': 'Have I Been Pwned',
            'email': email,
            'message': 'Template ready for implementation'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# DeHashed - Comprehensive breach detection
# Cost: $21/month + $15/500 credits
# Focus: Email & account breach detection, comprehensive data
# =============================================================================
@app.route('/api/dehashed/scan', methods=['POST'])
def dehashed_scan():
    """
    DeHashed API integration
    - Email & account breach detection
    - Emails, usernames, IPs, breached credentials, phone
    - More comprehensive, clear and detailed data
    """
    try:
        data = request.get_json()
        email = data.get('email', '')
        username = data.get('username', '')
        ip = data.get('ip', '')
        
        # TODO: Implement DeHashed API integration
        # API endpoint: https://api.dehashed.com/search
        # Requires API key authentication
        
        return jsonify({
            'status': 'template',
            'service': 'DeHashed',
            'email': email,
            'username': username,
            'ip': ip,
            'message': 'Template ready for implementation'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# LeakCheck - Lightweight breach detection
# Cost: $70/OTP (One-Time Payment)
# Focus: Email addresses, fewer sources, focused approach
# =============================================================================
@app.route('/api/leakcheck/scan', methods=['POST'])
def leakcheck_scan():
    """
    LeakCheck API integration
    - Email addresses breach check
    - Lightweight, fewer sources
    - One-time payment model
    """
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        
        # TODO: Implement LeakCheck API integration
        # API endpoint: https://leakcheck.io/api/public
        # Check documentation for exact endpoints and authentication
        
        return jsonify({
            'status': 'template',
            'service': 'LeakCheck',
            'email': email,
            'message': 'Template ready for implementation'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# EasyDMARC - Email authentication analysis
# Cost: $36/month
# Focus: Domain email authentication (SPF, DKIM, DMARC records)
# =============================================================================
@app.route('/api/easydmarc/scan', methods=['POST'])
def easydmarc_scan():
    """
    EasyDMARC API integration
    - Domain security scoring
    - SPF, DKIM, DMARC records analysis
    - Email authentication focused
    """
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        # TODO: Implement EasyDMARC API integration
        # API endpoint: Check EasyDMARC documentation
        # Focus on SPF, DKIM, DMARC record validation
        
        return jsonify({
            'status': 'template',
            'service': 'EasyDMARC',
            'domain': domain,
            'message': 'Template ready for implementation'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# Whois API - Domain ownership & DNS information
# Cost: Free (from python whois library)
# Focus: Domain ownership, registrar, nameservers, blacklists
# =============================================================================
@app.route('/api/whois/scan', methods=['POST'])
def whois_scan():
    """
    Whois API integration
    - Domain ownership & DNS info
    - Registrar, nameservers, blacklists
    - Complements EasyDMARC, no direct overlap
    """
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Get WHOIS information using python-whois library
        w = whois.whois(domain)
        
        # Extract and format the data
        whois_data = {
            'status': 'success',
            'domain': domain,
            'registrar': getattr(w, 'registrar', None),
            'creation_date': str(w.creation_date[0]) if isinstance(getattr(w, 'creation_date', None), list) and w.creation_date else str(getattr(w, 'creation_date', None)) if getattr(w, 'creation_date', None) else None,
            'expiration_date': str(w.expiration_date[0]) if isinstance(getattr(w, 'expiration_date', None), list) and w.expiration_date else str(getattr(w, 'expiration_date', None)) if getattr(w, 'expiration_date', None) else None,
            'updated_date': str(w.updated_date[0]) if isinstance(getattr(w, 'updated_date', None), list) and w.updated_date else str(getattr(w, 'updated_date', None)) if getattr(w, 'updated_date', None) else None,
            'nameservers': list(getattr(w, 'name_servers', [])) if getattr(w, 'name_servers', None) else [],
            'domain_status': getattr(w, 'status', []) if getattr(w, 'status', None) else [],
            'emails': getattr(w, 'emails', []) if getattr(w, 'emails', None) else [],
            'country': getattr(w, 'country', None),
            'state': getattr(w, 'state', None),
            'city': getattr(w, 'city', None),
            'address': getattr(w, 'address', None),
            'zipcode': getattr(w, 'zipcode', None),
            'org': getattr(w, 'org', None),
            'registrant_name': getattr(w, 'name', None)
        }
        
        # Clean up None values and empty lists
        whois_data = {k: v for k, v in whois_data.items() if v is not None and v != [] and v != ''}
        
        # Add security assessment
        security_assessment = {
            'privacy_protected': 'privacy' in str(w).lower() or 'redacted' in str(w).lower(),
            'days_until_expiry': None,
            'risk_level': 'low'
        }
        
        # Calculate days until expiry if expiration date is available
        if whois_data.get('expiration_date'):
            try:
                from datetime import datetime
                exp_date = datetime.strptime(whois_data['expiration_date'].split(' ')[0], '%Y-%m-%d')
                days_until_expiry = (exp_date - datetime.now()).days
                security_assessment['days_until_expiry'] = days_until_expiry
                
                if days_until_expiry < 30:
                    security_assessment['risk_level'] = 'high'
                elif days_until_expiry < 90:
                    security_assessment['risk_level'] = 'medium'
            except:
                pass
        
        whois_data['security_assessment'] = security_assessment
        
        return jsonify(whois_data)
    
    except Exception as e:
        print(f"WHOIS Error for domain {domain}: {str(e)}")  # Debug logging
        return jsonify({
            'status': 'error',
            'domain': domain if 'domain' in locals() else data.get('domain', '') if 'data' in locals() else '',
            'error': str(e),
            'message': 'Failed to retrieve WHOIS information'
        }), 200  # Return 200 so frontend can handle the error response

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
        
        results = {
            'scan_type': scan_type,
            'domain': domain,
            'email': email,
            'services': []
        }
        
        # TODO: Implement combined scanning logic
        # Based on scan_type, call appropriate service endpoints
        # Aggregate and correlate results
        # Generate comprehensive security assessment
        
        if scan_type in ['domain', 'both'] and domain:
            # Call EasyDMARC and Whois APIs
            results['services'].extend(['EasyDMARC', 'Whois'])
        
        if scan_type in ['email', 'both'] and email:
            # Call HIBP, DeHashed, LeakCheck APIs
            results['services'].extend(['HIBP', 'DeHashed', 'LeakCheck'])
        
        results['message'] = 'Combined scan template ready for implementation'
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8000)
