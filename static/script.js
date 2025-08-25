document.addEventListener('DOMContentLoaded', function() {
    const scanBtn = document.getElementById('scanBtn');
    const scanType = document.getElementById('scanType');
    const domainInput = document.getElementById('domainInput');
    const emailInput = document.getElementById('emailInput');
    const resultsSection = document.getElementById('resultsSection');
    const domainResults = document.getElementById('domainResults');
    const emailResults = document.getElementById('emailResults');
    const securityResults = document.getElementById('securityResults');
    const buttonText = document.querySelector('.button-text');
    const loadingSpinner = document.querySelector('.loading-spinner');

    // Handle scan type changes
    scanType.addEventListener('change', function() {
        const type = this.value;
        if (type === 'domain') {
            domainInput.style.display = 'block';
            emailInput.style.display = 'none';
            domainInput.required = true;
            emailInput.required = false;
        } else if (type === 'email') {
            domainInput.style.display = 'none';
            emailInput.style.display = 'block';
            domainInput.required = false;
            emailInput.required = true;
        } else {
            domainInput.style.display = 'block';
            emailInput.style.display = 'block';
            domainInput.required = true;
            emailInput.required = true;
        }
    });

    // Handle scan button click
    scanBtn.addEventListener('click', async function() {
        const type = scanType.value;
        const domain = domainInput.value.trim();
        const email = emailInput.value.trim();

        // Validation
        if (type === 'domain' && !domain) {
            showError('Please enter a domain to scan');
            return;
        }
        if (type === 'email' && !email) {
            showError('Please enter an email to scan');
            return;
        }
        if (type === 'both' && (!domain || !email)) {
            showError('Please enter both domain and email to scan');
            return;
        }

        // Show loading state
        setLoadingState(true);
        resultsSection.style.display = 'none';

        try {
            // For now, only call whois scan for domain scans
            let response;
            if (type === 'domain' && domain) {
                response = await fetch('/api/whois/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        domain: domain
                    })
                });
            } else {
                // For other scan types, show placeholder message
                displayPlaceholderResults(type);
                return;
            }

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            displayWhoisResults(data);
        } catch (error) {
            console.error('Scan error:', error);
            showError(`Scan failed: ${error.message}`);
        } finally {
            setLoadingState(false);
        }
    });

    function setLoadingState(loading) {
        if (loading) {
            buttonText.style.display = 'none';
            loadingSpinner.style.display = 'inline-block';
            scanBtn.disabled = true;
        } else {
            buttonText.style.display = 'inline-block';
            loadingSpinner.style.display = 'none';
            scanBtn.disabled = false;
        }
    }

    function showError(message) {
        resultsSection.style.display = 'block';
        domainResults.style.display = 'none';
        emailResults.style.display = 'none';
        securityResults.style.display = 'block';
        
        document.getElementById('securityContent').innerHTML = `
            <div style="color: #e74c3c; font-weight: bold;">
                <span class="status-indicator status-error"></span>
                Error: ${message}
            </div>
        `;
    }

    function displayResults(data, scanType) {
        resultsSection.style.display = 'block';
        
        // Show/hide relevant result cards
        domainResults.style.display = (scanType === 'domain' || scanType === 'both') ? 'block' : 'none';
        emailResults.style.display = (scanType === 'email' || scanType === 'both') ? 'block' : 'none';
        securityResults.style.display = 'block';

        // Display domain results
        if (data.domain && (scanType === 'domain' || scanType === 'both')) {
            displayDomainResults(data.domain);
        }

        // Display email results
        if (data.email && (scanType === 'email' || scanType === 'both')) {
            displayEmailResults(data.email);
        }

        // Display security assessment
        if (data.security) {
            displaySecurityResults(data.security);
        }
    }

    function displayDomainResults(domainData) {
        const content = document.getElementById('domainContent');
        let html = '';

        if (domainData.whois) {
            html += `
                <div class="result-item">
                    <strong>WHOIS Information:</strong><br>
                    <span class="status-indicator status-${domainData.whois.status}"></span>
                    Registrar: ${domainData.whois.registrar || 'N/A'}<br>
                    Created: ${domainData.whois.created || 'N/A'}<br>
                    Expires: ${domainData.whois.expires || 'N/A'}
                </div>
            `;
        }

        if (domainData.dns) {
            html += `
                <div class="result-item">
                    <strong>DNS Records:</strong><br>
                    ${domainData.dns.map(record => 
                        `<span class="status-indicator status-info"></span>${record.type}: ${record.value}`
                    ).join('<br>')}
                </div>
            `;
        }

        if (domainData.ssl) {
            html += `
                <div class="result-item">
                    <strong>SSL Certificate:</strong><br>
                    <span class="status-indicator status-${domainData.ssl.valid ? 'success' : 'error'}"></span>
                    Valid: ${domainData.ssl.valid ? 'Yes' : 'No'}<br>
                    Expires: ${domainData.ssl.expires || 'N/A'}
                </div>
            `;
        }

        content.innerHTML = html || '<p>No domain data available</p>';
    }

    function displayEmailResults(emailData) {
        const content = document.getElementById('emailContent');
        let html = '';

        if (emailData.validation) {
            html += `
                <div class="result-item">
                    <strong>Email Validation:</strong><br>
                    <span class="status-indicator status-${emailData.validation.valid ? 'success' : 'error'}"></span>
                    Valid: ${emailData.validation.valid ? 'Yes' : 'No'}<br>
                    Deliverable: ${emailData.validation.deliverable || 'Unknown'}
                </div>
            `;
        }

        if (emailData.mx) {
            html += `
                <div class="result-item">
                    <strong>MX Records:</strong><br>
                    ${emailData.mx.map(mx => 
                        `<span class="status-indicator status-info"></span>${mx.exchange} (Priority: ${mx.priority})`
                    ).join('<br>')}
                </div>
            `;
        }

        if (emailData.security) {
            html += `
                <div class="result-item">
                    <strong>Email Security:</strong><br>
                    <span class="status-indicator status-${emailData.security.spf ? 'success' : 'warning'}"></span>SPF: ${emailData.security.spf ? 'Configured' : 'Not Found'}<br>
                    <span class="status-indicator status-${emailData.security.dkim ? 'success' : 'warning'}"></span>DKIM: ${emailData.security.dkim ? 'Configured' : 'Not Found'}<br>
                    <span class="status-indicator status-${emailData.security.dmarc ? 'success' : 'warning'}"></span>DMARC: ${emailData.security.dmarc ? 'Configured' : 'Not Found'}
                </div>
            `;
        }

        content.innerHTML = html || '<p>No email data available</p>';
    }

    function displaySecurityResults(securityData) {
        const content = document.getElementById('securityContent');
        let html = '';

        if (securityData.riskScore !== undefined) {
            const riskLevel = securityData.riskScore > 70 ? 'error' : securityData.riskScore > 40 ? 'warning' : 'success';
            html += `
                <div class="result-item">
                    <strong>Risk Assessment:</strong><br>
                    <span class="status-indicator status-${riskLevel}"></span>
                    Risk Score: ${securityData.riskScore}/100<br>
                    Level: ${securityData.riskLevel || 'Unknown'}
                </div>
            `;
        }

        if (securityData.threats && securityData.threats.length > 0) {
            html += `
                <div class="result-item">
                    <strong>Detected Threats:</strong><br>
                    ${securityData.threats.map(threat => 
                        `<span class="status-indicator status-error"></span>${threat}`
                    ).join('<br>')}
                </div>
            `;
        }

        if (securityData.reputation) {
            html += `
                <div class="result-item">
                    <strong>Reputation:</strong><br>
                    <span class="status-indicator status-${securityData.reputation.status}"></span>
                    Status: ${securityData.reputation.description || 'Unknown'}
                </div>
            `;
        }

        content.innerHTML = html || '<p>Security assessment completed successfully</p>';
    }

    function displayPlaceholderResults(scanType) {
        resultsSection.style.display = 'block';
        domainResults.style.display = 'none';
        emailResults.style.display = 'none';
        securityResults.style.display = 'block';
        
        let message = '';
        if (scanType === 'email') {
            message = 'Email scanning coming soon! Will include HIBP, DeHashed, and LeakCheck breach detection.';
        } else if (scanType === 'both') {
            message = 'Combined scanning coming soon! Will include all domain and email security services.';
        }
        
        document.getElementById('securityContent').innerHTML = `
            <div style="color: #00c3f5; font-weight: bold;">
                <span class="status-indicator status-info"></span>
                ${message}
            </div>
        `;
    }

    function displayWhoisResults(data) {
        resultsSection.style.display = 'block';
        domainResults.style.display = 'block';
        emailResults.style.display = 'none';
        securityResults.style.display = 'block';

        // Display WHOIS domain results
        const domainContent = document.getElementById('domainContent');
        let domainHtml = '';

        if (data.status === 'success') {
            domainHtml += `
                <div class="result-item">
                    <strong>Domain Information:</strong><br>
                    <span class="status-indicator status-success"></span>Domain: ${data.domain}<br>
                    ${data.registrar ? `Registrar: ${data.registrar}<br>` : ''}
                    ${data.creation_date ? `Created: ${data.creation_date}<br>` : ''}
                    ${data.expiration_date ? `Expires: ${data.expiration_date}<br>` : ''}
                    ${data.updated_date ? `Updated: ${data.updated_date}<br>` : ''}
                </div>
            `;

            if (data.nameservers && data.nameservers.length > 0) {
                domainHtml += `
                    <div class="result-item">
                        <strong>Nameservers:</strong><br>
                        ${data.nameservers.map(ns => 
                            `<span class="status-indicator status-info"></span>${ns}`
                        ).join('<br>')}
                    </div>
                `;
            }

            if (data.org || data.registrant_name || data.country) {
                domainHtml += `
                    <div class="result-item">
                        <strong>Registrant Information:</strong><br>
                        ${data.org ? `<span class="status-indicator status-info"></span>Organization: ${data.org}<br>` : ''}
                        ${data.registrant_name ? `<span class="status-indicator status-info"></span>Name: ${data.registrant_name}<br>` : ''}
                        ${data.country ? `<span class="status-indicator status-info"></span>Country: ${data.country}<br>` : ''}
                        ${data.state ? `<span class="status-indicator status-info"></span>State: ${data.state}<br>` : ''}
                        ${data.city ? `<span class="status-indicator status-info"></span>City: ${data.city}<br>` : ''}
                    </div>
                `;
            }
        } else if (data.status === 'error') {
            domainHtml = `
                <div class="result-item">
                    <span class="status-indicator status-error"></span>
                    Error: ${data.error || 'Failed to retrieve WHOIS information'}
                </div>
            `;
        }

        domainContent.innerHTML = domainHtml;

        // Display security assessment
        const securityContent = document.getElementById('securityContent');
        let securityHtml = '';

        if (data.security_assessment) {
            const assessment = data.security_assessment;
            const riskColor = assessment.risk_level === 'high' ? 'error' : 
                             assessment.risk_level === 'medium' ? 'warning' : 'success';
            
            securityHtml += `
                <div class="result-item">
                    <strong>WHOIS Security Assessment:</strong><br>
                    <span class="status-indicator status-${riskColor}"></span>
                    Risk Level: ${assessment.risk_level.toUpperCase()}<br>
                    ${assessment.days_until_expiry !== null ? 
                        `Days Until Expiry: ${assessment.days_until_expiry}<br>` : ''}
                    Privacy Protected: ${assessment.privacy_protected ? 'Yes' : 'No'}
                </div>
            `;

            // Add placeholder sections for other services
            securityHtml += `
                <div class="result-item" style="opacity: 0.6;">
                    <strong>Email Breach Detection:</strong><br>
                    <span class="status-indicator status-info"></span>
                    HIBP, DeHashed, LeakCheck - Coming Soon
                </div>
                <div class="result-item" style="opacity: 0.6;">
                    <strong>Email Authentication:</strong><br>
                    <span class="status-indicator status-info"></span>
                    EasyDMARC SPF/DKIM/DMARC Analysis - Coming Soon
                </div>
            `;
        }

        securityContent.innerHTML = securityHtml || '<p>Security assessment completed</p>';
    }

    // Initialize form state
    scanType.dispatchEvent(new Event('change'));
});
