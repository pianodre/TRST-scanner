"""
API routes module for scanner endpoints.
"""

from flask import jsonify, request
from auth import require_login
from services.domain_services import whois_scan, easydmarc_scan, dmarc_scan, spf_scan
from services.email_services import leakcheck_scan, hibp_scan, dehashed_scan
from services.security_utils import assess_combined_risk, format_security_message


def create_scan_route(service_function, param_extractors):
    """Generic route handler to eliminate duplicate code"""
    @require_login
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


def hibp_scan_route():
    """HIBP (Have I Been Pwned) - Email breach detection"""
    return create_scan_route(hibp_scan, {'email': lambda d: d.get('email', '').strip()})()


def dehashed_scan_route():
    """DeHashed - Comprehensive breach detection"""
    return create_scan_route(dehashed_scan, {
        'email': lambda d: d.get('email', ''),
        'username': lambda d: d.get('username', ''),
        'ip': lambda d: d.get('ip', '')
    })()


def leakcheck_scan_route():
    """LeakCheck - Lightweight breach detection"""
    return create_scan_route(leakcheck_scan, {'email': lambda d: d.get('email', '').strip()})()


def easydmarc_scan_route():
    """EasyDMARC - Email authentication analysis"""
    return create_scan_route(easydmarc_scan, {'domain': lambda d: d.get('domain', '').strip()})()


def whois_scan_route():
    """Whois API - Domain ownership & DNS information"""
    return create_scan_route(whois_scan, {'domain': lambda d: d.get('domain', '').strip()})()


def dmarc_scan_route():
    """DMARC Scanner - DNS-based DMARC record analysis"""
    return create_scan_route(dmarc_scan, {'domain': lambda d: d.get('domain', '').strip()})()


def spf_scan_route():
    """SPF Scanner - DNS-based SPF record analysis"""
    return create_scan_route(spf_scan, {'domain': lambda d: d.get('domain', '').strip()})()


@require_login
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
            
            # Add SPF check for email domain
            if '@' in email:
                email_domain = email.split('@')[1]
                spf_result, _ = spf_scan(email_domain)
                if spf_result.get('status') in ['Good', 'Okay', 'Bad']:
                    if not email_data:
                        email_data = {}
                    email_data['spf_data'] = spf_result
        
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
