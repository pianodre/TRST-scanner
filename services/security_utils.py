def assess_combined_risk(domain_data=None, email_data=None):
    """
    Assess combined security risk from domain and email data
    Returns overall risk level and recommendations
    """
    risk_factors = []
    risk_score = 0
    recommendations = []
    
    # Domain risk assessment
    if domain_data and domain_data.get('security_assessment'):
        domain_risk = domain_data['security_assessment']
        
        if domain_risk.get('risk_level') == 'high':
            risk_score += 40
            risk_factors.append('Domain expiring soon')
        elif domain_risk.get('risk_level') == 'medium':
            risk_score += 20
            risk_factors.append('Domain expiring within 90 days')
        
        if not domain_risk.get('privacy_protected'):
            risk_score += 10
            risk_factors.append('Domain registration not privacy protected')
            recommendations.append('Consider enabling domain privacy protection')
    
    # Email risk assessment
    if email_data and email_data.get('breach_count', 0) > 0:
        breach_count = email_data['breach_count']
        
        if breach_count >= 5:
            risk_score += 50
            risk_factors.append(f'Email found in {breach_count} breaches')
            recommendations.append('Change passwords immediately and enable 2FA')
        elif breach_count >= 2:
            risk_score += 30
            risk_factors.append(f'Email found in {breach_count} breaches')
            recommendations.append('Monitor accounts closely and consider password changes')
        else:
            risk_score += 15
            risk_factors.append(f'Email found in {breach_count} breach(es)')
            recommendations.append('Monitor account activity')
    
    # Determine overall risk level
    if risk_score >= 60:
        overall_risk = 'high'
    elif risk_score >= 30:
        overall_risk = 'medium'
    else:
        overall_risk = 'low'
    
    return {
        'overall_risk': overall_risk,
        'risk_score': min(risk_score, 100),  # Cap at 100
        'risk_factors': risk_factors,
        'recommendations': recommendations
    }


def format_security_message(risk_level, risk_factors=None):
    """
    Format a user-friendly security message based on risk level
    """
    messages = {
        'low': 'Security status looks good. Continue monitoring.',
        'medium': 'Some security concerns detected. Review recommendations.',
        'high': 'High security risk detected. Take immediate action.'
    }
    
    base_message = messages.get(risk_level, 'Security assessment completed.')
    
    if risk_factors:
        factor_text = ', '.join(risk_factors[:3])  # Show top 3 factors
        return f"{base_message} Issues: {factor_text}"
    
    return base_message
