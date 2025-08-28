from leakcheck import LeakCheckAPI_Public


def leakcheck_scan(email):
    """
    LeakCheck API integration
    - Email addresses breach check
    - Uses free public API (no authentication required)
    - Lightweight, fewer sources
    """
    try:
        if not email:
            return {'error': 'Email is required'}, 400
        
        # Initialize LeakCheck public API (free, no authentication required)
        public_api = LeakCheckAPI_Public()
        
        # Perform the lookup
        result = public_api.lookup(query=email)
        
        # Process the response
        if result and 'success' in result and result['success']:
            # Extract breach information
            sources = result.get('sources', [])
            found_count = len(sources)
            
            # Format the response
            response_data = {
                'status': 'success',
                'service': 'LeakCheck',
                'email': email,
                'found': found_count > 0,
                'breach_count': found_count,
                'sources': sources[:10],  # Limit to first 10 sources for display
                'total_sources': found_count,
                'message': f'Found in {found_count} breach(es)' if found_count > 0 else 'No breaches found'
            }
            
            # Add risk assessment
            if found_count == 0:
                response_data['risk_level'] = 'low'
                response_data['risk_message'] = 'Email not found in known breaches'
            elif found_count <= 2:
                response_data['risk_level'] = 'medium'
                response_data['risk_message'] = 'Email found in few breaches - monitor closely'
            else:
                response_data['risk_level'] = 'high'
                response_data['risk_message'] = 'Email found in multiple breaches - high risk'
                
        else:
            # Handle API errors or no results
            response_data = {
                'status': 'success',
                'service': 'LeakCheck',
                'email': email,
                'found': False,
                'breach_count': 0,
                'sources': [],
                'total_sources': 0,
                'risk_level': 'low',
                'message': 'No breaches found or API error',
                'risk_message': 'Unable to determine breach status'
            }
        
        return response_data, 200
    
    except Exception as e:
        print(f"LeakCheck Error for email {email}: {str(e)}")  # Debug logging
        
        # Handle "Not found" errors more gracefully
        error_message = str(e).lower()
        if 'not found' in error_message or 'api responded with an error: not found' in error_message:
            return {
                'status': 'success',
                'service': 'LeakCheck',
                'email': email,
                'found': False,
                'breach_count': 0,
                'sources': [],
                'total_sources': 0,
                'risk_level': 'low',
                'message': 'No breaches or leaks found',
                'risk_message': 'Email not found in known breaches'
            }, 200
        
        return {
            'status': 'error',
            'service': 'LeakCheck',
            'email': email,
            'error': str(e),
            'message': 'Failed to check email against LeakCheck database'
        }, 200  # Return 200 so frontend can handle the error response


def hibp_scan(email):
    """
    Have I Been Pwned API integration
    - Email breach detection
    - Quick email breach check
    - Limited sources, mostly major breaches
    """
    try:
        if not email:
            return {'error': 'Email is required'}, 400
        
        # TODO: Implement HIBP API integration
        # API endpoint: https://haveibeenpwned.com/api/v3/breachedaccount/{email}
        # Requires API key and User-Agent header
        
        return {
            'status': 'template',
            'service': 'Have I Been Pwned',
            'email': email,
            'message': 'Template ready for implementation'
        }, 200
    
    except Exception as e:
        return {'error': str(e)}, 500


def dehashed_scan(email, username=None, ip=None):
    """
    DeHashed API integration
    - Email & account breach detection
    - Emails, usernames, IPs, breached credentials, phone
    - More comprehensive, clear and detailed data
    """
    try:
        if not email and not username and not ip:
            return {'error': 'Email, username, or IP is required'}, 400
        
        # TODO: Implement DeHashed API integration
        # API endpoint: https://api.dehashed.com/search
        # Requires API key authentication
        
        return {
            'status': 'template',
            'service': 'DeHashed',
            'email': email,
            'username': username,
            'ip': ip,
            'message': 'Template ready for implementation'
        }, 200
    
    except Exception as e:
        return {'error': str(e)}, 500
