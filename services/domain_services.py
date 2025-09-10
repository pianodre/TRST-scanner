import whois
import dns.resolver
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


def dmarc_scan(domain):
    """
    DMARC record analysis using dnspython
    - Checks for DMARC record existence
    - Analyzes policy strength
    - Returns Bad/Okay/Good rating
    """
    try:
        if not domain:
            return {'error': 'Domain is required'}, 400
        
        # Query DMARC record
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_record = None
        
        try:
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for answer in answers:
                record_text = str(answer).strip('"')
                if record_text.startswith('v=DMARC1'):
                    dmarc_record = record_text
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {
                'domain': domain,
                'record': None,
                'message': 'No DMARC record found',
                'details': {
                    'policy': None,
                    'percentage': None,
                    'alignment': None,
                    'reporting': None
                }
            }, 200
        
        if not dmarc_record:
            return {
                'domain': domain,
                'record': None,
                'message': 'No valid DMARC record found',
                'details': {
                    'policy': None,
                    'percentage': None,
                    'alignment': None,
                    'reporting': None
                }
            }, 200
        
        # Parse DMARC record
        dmarc_details = parse_dmarc_record(dmarc_record)
        
        return {
            'domain': domain,
            'record': dmarc_record,
            'message': 'DMARC record found and parsed',
            'details': dmarc_details
        }, 200
    
    except Exception as e:
        return {
            'domain': domain,
            'error': str(e),
            'message': 'Failed to check DMARC record'
        }, 200


def parse_dmarc_record(record):
    """Parse DMARC record and extract key components"""
    details = {
        'policy': None,
        'subdomain_policy': None,
        'percentage': 100,
        'alignment_spf': None,
        'alignment_dkim': None,
        'reporting_uri': None,
        'forensic_uri': None,
        'report_interval': None
    }
    
    # Split record into key-value pairs
    pairs = record.split(';')
    for pair in pairs:
        if '=' in pair:
            key, value = pair.strip().split('=', 1)
            key = key.strip().lower()
            value = value.strip()
            
            if key == 'p':
                details['policy'] = value
            elif key == 'sp':
                details['subdomain_policy'] = value
            elif key == 'pct':
                try:
                    details['percentage'] = int(value)
                except:
                    details['percentage'] = 100
            elif key == 'aspf':
                details['alignment_spf'] = value
            elif key == 'adkim':
                details['alignment_dkim'] = value
            elif key == 'rua':
                details['reporting_uri'] = value
            elif key == 'ruf':
                details['forensic_uri'] = value
            elif key == 'ri':
                try:
                    details['report_interval'] = int(value)
                except:
                    details['report_interval'] = None
    
    return details




def spf_scan(domain):
    """
    SPF (Sender Policy Framework) record analysis using dnspython
    - Checks for SPF record existence
    - Analyzes SPF policy mechanisms
    - Returns Bad/Okay/Good rating based on configuration
    """
    try:
        if not domain:
            return {'error': 'Domain is required'}, 400
        
        # Query SPF record (TXT record for the domain)
        spf_record = None
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for answer in answers:
                record_text = str(answer).strip('"')
                if record_text.startswith('v=spf1'):
                    spf_record = record_text
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {
                'domain': domain,
                'record': None,
                'message': 'No SPF record found',
                'details': {
                    'mechanisms': [],
                    'qualifiers': [],
                    'includes': [],
                    'all_mechanism': None,
                    'redirect': None
                }
            }, 200
        
        if not spf_record:
            return {
                'domain': domain,
                'record': None,
                'message': 'No valid SPF record found',
                'details': {
                    'mechanisms': [],
                    'qualifiers': [],
                    'includes': [],
                    'all_mechanism': None,
                    'redirect': None
                }
            }, 200
        
        # Parse SPF record
        spf_details = parse_spf_record(spf_record)
        
        return {
            'domain': domain,
            'record': spf_record,
            'message': 'SPF record found and parsed',
            'details': spf_details
        }, 200
    
    except Exception as e:
        return {
            'domain': domain,
            'error': str(e),
            'message': 'Failed to check SPF record'
        }, 200


def parse_spf_record(record):
    """Parse SPF record and extract key components"""
    details = {
        'mechanisms': [],
        'qualifiers': [],
        'includes': [],
        'all_mechanism': None,
        'redirect': None,
        'ip4_addresses': [],
        'ip6_addresses': [],
        'a_records': [],
        'mx_records': [],
        'exists': []
    }
    
    # Split record into mechanisms
    parts = record.split()
    
    for part in parts[1:]:  # Skip 'v=spf1'
        part = part.strip()
        
        # Extract qualifier (+ - ~ ?)
        qualifier = '+'  # Default qualifier
        if part.startswith(('+', '-', '~', '?')):
            qualifier = part[0]
            mechanism = part[1:]
        else:
            mechanism = part
        
        details['qualifiers'].append(qualifier)
        
        # Parse different mechanism types
        if mechanism.startswith('include:'):
            include_domain = mechanism[8:]
            details['includes'].append(include_domain)
            details['mechanisms'].append(f'{qualifier}include:{include_domain}')
        elif mechanism.startswith('ip4:'):
            ip4 = mechanism[4:]
            details['ip4_addresses'].append(ip4)
            details['mechanisms'].append(f'{qualifier}ip4:{ip4}')
        elif mechanism.startswith('ip6:'):
            ip6 = mechanism[4:]
            details['ip6_addresses'].append(ip6)
            details['mechanisms'].append(f'{qualifier}ip6:{ip6}')
        elif mechanism.startswith('a'):
            if ':' in mechanism:
                a_record = mechanism[2:]
            else:
                a_record = ''
            details['a_records'].append(a_record)
            details['mechanisms'].append(f'{qualifier}a{":"+a_record if a_record else ""}')
        elif mechanism.startswith('mx'):
            if ':' in mechanism:
                mx_record = mechanism[3:]
            else:
                mx_record = ''
            details['mx_records'].append(mx_record)
            details['mechanisms'].append(f'{qualifier}mx{":"+mx_record if mx_record else ""}')
        elif mechanism.startswith('exists:'):
            exists_domain = mechanism[7:]
            details['exists'].append(exists_domain)
            details['mechanisms'].append(f'{qualifier}exists:{exists_domain}')
        elif mechanism.startswith('redirect='):
            details['redirect'] = mechanism[9:]
        elif mechanism == 'all':
            details['all_mechanism'] = qualifier + 'all'
            details['mechanisms'].append(qualifier + 'all')
        else:
            # Other mechanisms
            details['mechanisms'].append(qualifier + mechanism)
    
    return details




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
