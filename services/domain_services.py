import whois
from datetime import datetime


def whois_scan(domain):
    """
    Whois API integration
    - Domain ownership & DNS info
    - Registrar, nameservers, blacklists
    - Complements EasyDMARC, no direct overlap
    """
    try:
        if not domain:
            return {'error': 'Domain is required'}, 400
        
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
        
        return whois_data, 200
    
    except Exception as e:
        print(f"WHOIS Error for domain {domain}: {str(e)}")  # Debug logging
        return {
            'status': 'error',
            'domain': domain,
            'error': str(e),
            'message': 'Failed to retrieve WHOIS information'
        }, 200  # Return 200 so frontend can handle the error response


def easydmarc_scan(domain):
    """
    EasyDMARC API integration
    - Domain security scoring
    - SPF, DKIM, DMARC records analysis
    - Email authentication focused
    """
    try:
        if not domain:
            return {'error': 'Domain is required'}, 400
        
        # TODO: Implement EasyDMARC API integration
        # API endpoint: Check EasyDMARC documentation
        # Focus on SPF, DKIM, DMARC record validation
        
        return {
            'status': 'template',
            'service': 'EasyDMARC',
            'domain': domain,
            'message': 'Template ready for implementation'
        }, 200
    
    except Exception as e:
        return {'error': str(e)}, 500
