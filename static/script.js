// Logout function
function logout() {
    if (confirm('Are you sure you want to logout?')) {
        window.location.href = '/logout';
    }
}

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
            let response;
            if (type === 'domain' && domain) {
                // Call WHOIS, DMARC, and SPF APIs for domain scanning
                const [whoisResponse, dmarcResponse, spfResponse] = await Promise.all([
                    fetch('/api/whois/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain: domain })
                    }),
                    fetch('/api/dmarc/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain: domain })
                    }),
                    fetch('/api/spf/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain: domain })
                    })
                ]);
                
                if (!whoisResponse.ok || !dmarcResponse.ok || !spfResponse.ok) {
                    throw new Error(`HTTP error! WHOIS: ${whoisResponse.status}, DMARC: ${dmarcResponse.status}, SPF: ${spfResponse.status}`);
                }
                
                const whoisData = await whoisResponse.json();
                const dmarcData = await dmarcResponse.json();
                const spfData = await spfResponse.json();
                
                displayDomainResults(whoisData, dmarcData, spfData);
            } else if (type === 'email' && email) {
                // For email scans, also get SPF data for the email domain
                const emailDomain = email.includes('@') ? email.split('@')[1] : null;
                
                const requests = [
                    fetch('/api/leakcheck/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: email })
                    })
                ];
                
                // Add SPF scan if we have a domain
                if (emailDomain) {
                    requests.push(
                        fetch('/api/spf/scan', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ domain: emailDomain })
                        })
                    );
                }
                
                const responses = await Promise.all(requests);
                
                if (!responses[0].ok) {
                    throw new Error(`HTTP error! status: ${responses[0].status}`);
                }
                
                const emailData = await responses[0].json();
                let spfData = null;
                
                if (responses[1] && responses[1].ok) {
                    spfData = await responses[1].json();
                }
                
                displayEmailResults(emailData, spfData);
            } else if (type === 'both' && domain && email) {
                // Call all APIs for comprehensive scanning including SPF
                const [whoisResponse, dmarcResponse, spfResponse, emailResponse] = await Promise.all([
                    fetch('/api/whois/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain: domain })
                    }),
                    fetch('/api/dmarc/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain: domain })
                    }),
                    fetch('/api/spf/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain: domain })
                    }),
                    fetch('/api/leakcheck/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: email })
                    })
                ]);
                
                if (!whoisResponse.ok || !dmarcResponse.ok || !spfResponse.ok || !emailResponse.ok) {
                    throw new Error('One or more scans failed');
                }
                
                const whoisData = await whoisResponse.json();
                const dmarcData = await dmarcResponse.json();
                const spfData = await spfResponse.json();
                const emailData = await emailResponse.json();
                displayCombinedResults(whoisData, dmarcData, spfData, emailData);
            } else {
                displayPlaceholderResults(type);
                return;
            }
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

    // New function to display domain results with WHOIS, DMARC, and SPF data
    function displayDomainResults(whoisData, dmarcData, spfData) {
        resultsSection.style.display = 'block';
        domainResults.style.display = 'block';
        emailResults.style.display = 'none';
        securityResults.style.display = 'block';
        
        const content = document.getElementById('domainContent');
        let html = '';

        // WHOIS Information
        if (whoisData && whoisData.status === 'success') {
            html += `
                <div class="result-item" style="margin-bottom: 20px;">
                    <strong>🏢 WHOIS Information:</strong><br>
                    <span class="status-indicator status-success"></span>
                    <strong>Domain:</strong> ${whoisData.domain || 'N/A'}<br>
                    <strong>Registrar:</strong> ${whoisData.registrar || 'N/A'}<br>
                    <strong>Created:</strong> ${whoisData.creation_date || 'N/A'}<br>
                    <strong>Expires:</strong> ${whoisData.expiration_date || 'N/A'}<br>
                    ${whoisData.nameservers && whoisData.nameservers.length > 0 ? 
                        `<strong>Nameservers:</strong> ${whoisData.nameservers.slice(0, 2).join(', ')}` : ''}
                </div>
            `;
        } else {
            html += `
                <div class="result-item" style="margin-bottom: 20px;">
                    <strong>🏢 WHOIS Information:</strong><br>
                    <span class="status-indicator status-error"></span>
                    Failed to retrieve WHOIS data
                </div>
            `;
        }

        // DMARC Information
        if (dmarcData) {
            const hasRecord = dmarcData.record ? 'status-success' : 'status-warning';
            
            html += `
                <div class="result-item">
                    <strong>🔒 DMARC Analysis:</strong><br>
                    <span class="status-indicator ${hasRecord}"></span>
                    <strong>Message:</strong> ${dmarcData.message || 'N/A'}<br>
                    ${dmarcData.record ? `<strong>Record:</strong> ${dmarcData.record}<br>` : ''}
                    ${dmarcData.details && dmarcData.details.policy ? 
                        `<strong>Policy:</strong> ${dmarcData.details.policy}<br>` : ''}
                    ${dmarcData.details && dmarcData.details.percentage ? 
                        `<strong>Coverage:</strong> ${dmarcData.details.percentage}%<br>` : ''}
                    ${dmarcData.details && dmarcData.details.reporting_uri ? 
                        `<strong>Reporting:</strong> Configured<br>` : ''}
                </div>
            `;
        }

        // SPF Information
        if (spfData) {
            const hasRecord = spfData.record ? 'status-success' : 'status-warning';
            
            html += `
                <div class="result-item">
                    <strong>📧 SPF Analysis:</strong><br>
                    <span class="status-indicator ${hasRecord}"></span>
                    <strong>Message:</strong> ${spfData.message || 'N/A'}<br>
                    ${spfData.record ? `<strong>Record:</strong> ${spfData.record}<br>` : ''}
                    ${spfData.details && spfData.details.all_mechanism ? 
                        `<strong>All Mechanism:</strong> ${spfData.details.all_mechanism}<br>` : ''}
                    ${spfData.details && spfData.details.includes && spfData.details.includes.length > 0 ? 
                        `<strong>Includes:</strong> ${spfData.details.includes.slice(0, 3).join(', ')}${spfData.details.includes.length > 3 ? '...' : ''}<br>` : ''}
                    ${spfData.details && spfData.details.ip4_addresses && spfData.details.ip4_addresses.length > 0 ? 
                        `<strong>IP4 Addresses:</strong> ${spfData.details.ip4_addresses.slice(0, 2).join(', ')}${spfData.details.ip4_addresses.length > 2 ? '...' : ''}<br>` : ''}
                </div>
            `;
        }

        content.innerHTML = html;
        
        // Show security assessment
        displaySecurityAssessment(whoisData, dmarcData, spfData);
    }

    // Function to display combined results (both domain and email)
    function displayCombinedResults(whoisData, dmarcData, spfData, emailData) {
        resultsSection.style.display = 'block';
        domainResults.style.display = 'block';
        emailResults.style.display = 'block';
        securityResults.style.display = 'block';
        
        // Display domain results
        const domainContent = document.getElementById('domainContent');
        let domainHtml = '';

        // WHOIS Information
        if (whoisData && whoisData.status === 'success') {
            domainHtml += `
                <div class="result-item" style="margin-bottom: 15px;">
                    <strong>🏢 WHOIS:</strong><br>
                    <span class="status-indicator status-success"></span>
                    ${whoisData.registrar || 'N/A'} | Expires: ${whoisData.expiration_date || 'N/A'}
                </div>
            `;
        }

        // DMARC Information
        if (dmarcData) {
            const hasRecord = dmarcData.record ? 'status-success' : 'status-warning';
            
            domainHtml += `
                <div class="result-item">
                    <strong>🔒 DMARC:</strong><br>
                    <span class="status-indicator ${hasRecord}"></span>
                    ${dmarcData.message || 'N/A'}
                </div>
            `;
        }

        // SPF Information
        if (spfData) {
            const hasRecord = spfData.record ? 'status-success' : 'status-warning';
            
            domainHtml += `
                <div class="result-item">
                    <strong>📧 SPF:</strong><br>
                    <span class="status-indicator ${hasRecord}"></span>
                    ${spfData.message || 'N/A'}
                </div>
            `;
        }

        domainContent.innerHTML = domainHtml;
        
        // Display email results
        displayLeakCheckResults(emailData);
        
        // Show combined security assessment
        displayCombinedSecurityAssessment(whoisData, dmarcData, spfData, emailData);
    }

    // Function to display security assessment for domain-only scans
    function displaySecurityAssessment(whoisData, dmarcData, spfData) {
        const content = document.getElementById('securityContent');
        let html = '';
        
        let riskScore = 0;
        let threats = [];
        
        // Assess WHOIS risk
        if (whoisData && whoisData.status === 'success') {
            riskScore += 25;
            if (whoisData.security_assessment) {
                if (whoisData.security_assessment.days_until_expiry < 30) {
                    threats.push('Domain expires soon');
                } else {
                    riskScore += 15;
                }
            }
        } else {
            threats.push('WHOIS data unavailable');
        }
        
        // Assess DMARC risk
        if (dmarcData) {
            if (dmarcData.record) {
                riskScore += 25;
                if (dmarcData.details && dmarcData.details.policy === 'none') {
                    threats.push('DMARC policy set to none');
                    riskScore -= 10;
                }
            } else {
                threats.push('No DMARC record found');
            }
        }
        
        // Assess SPF risk
        if (spfData) {
            if (spfData.record) {
                riskScore += 20;
                if (spfData.details && spfData.details.all_mechanism === '+all') {
                    threats.push('SPF allows all senders');
                    riskScore -= 15;
                }
            } else {
                threats.push('No SPF record found');
            }
        }
        
        const finalRisk = Math.max(0, 100 - riskScore);
        const riskLevel = finalRisk > 70 ? 'High' : finalRisk > 40 ? 'Medium' : 'Low';
        const riskClass = finalRisk > 70 ? 'status-error' : finalRisk > 40 ? 'status-warning' : 'status-success';
        
        html += `
            <div class="result-item">
                <strong>📊 Security Assessment:</strong><br>
                <span class="status-indicator ${riskClass}"></span>
                <strong>Risk Level:</strong> ${riskLevel} (${finalRisk}/100)<br>
                ${threats.length > 0 ? `<strong>Issues:</strong> ${threats.join(', ')}` : '<strong>Status:</strong> No major issues detected'}
            </div>
        `;
        
        content.innerHTML = html;
    }

    // Function to display combined security assessment
    function displayCombinedSecurityAssessment(whoisData, dmarcData, spfData, emailData) {
        const content = document.getElementById('securityContent');
        let html = '';
        
        let riskScore = 0;
        let threats = [];
        
        // Domain assessment
        if (whoisData && whoisData.status === 'success') {
            riskScore += 20;
        } else {
            threats.push('WHOIS issues');
        }
        
        if (dmarcData) {
            if (dmarcData.record) {
                riskScore += 20;
                if (dmarcData.details && dmarcData.details.policy === 'none') {
                    threats.push('DMARC policy set to none');
                    riskScore -= 10;
                }
            } else {
                threats.push('DMARC issues');
            }
        }
        
        if (spfData) {
            if (spfData.record) {
                riskScore += 15;
                if (spfData.details && spfData.details.all_mechanism === '+all') {
                    threats.push('SPF allows all senders');
                    riskScore -= 10;
                }
            } else {
                threats.push('SPF issues');
            }
        }
        
        // Email assessment
        if (emailData && emailData.status === 'success') {
            if (emailData.found && emailData.found.length > 0) {
                threats.push('Email found in breaches');
            } else {
                riskScore += 25;
            }
        }
        
        const finalRisk = Math.max(0, 100 - riskScore);
        const riskLevel = finalRisk > 70 ? 'High' : finalRisk > 40 ? 'Medium' : 'Low';
        const riskClass = finalRisk > 70 ? 'status-error' : finalRisk > 40 ? 'status-warning' : 'status-success';
        
        html += `
            <div class="result-item">
                <strong>📊 Combined Security Assessment:</strong><br>
                <span class="status-indicator ${riskClass}"></span>
                <strong>Overall Risk:</strong> ${riskLevel} (${finalRisk}/100)<br>
                ${threats.length > 0 ? `<strong>Issues:</strong> ${threats.join(', ')}` : '<strong>Status:</strong> All checks passed'}
            </div>
        `;
        
        content.innerHTML = html;
    }


    function displayEmailResults(emailData, spfData = null) {
        resultsSection.style.display = 'block';
        domainResults.style.display = 'none';
        emailResults.style.display = 'block';
        securityResults.style.display = 'block';
        
        const content = document.getElementById('emailContent');
        let html = '';
        
        // Display breach detection results
        if (emailData && emailData.status === 'success') {
            if (emailData.found && emailData.breach_count > 0) {
                html += `
                    <div class="result-item">
                        <strong>⚠️ Breach Detection:</strong><br>
                        <span class="status-indicator status-error"></span>
                        <strong>Email found in ${emailData.breach_count} breach(es)</strong><br>
                        ${emailData.sources && emailData.sources.length > 0 ? 
                            emailData.sources.slice(0, 5).map(source => `• ${source}`).join('<br>') : ''}
                        ${emailData.sources && emailData.sources.length > 5 ? `<br>... and ${emailData.sources.length - 5} more` : ''}
                    </div>
                `;
            } else {
                html += `
                    <div class="result-item">
                        <strong>✅ Breach Detection:</strong><br>
                        <span class="status-indicator status-success"></span>
                        No breaches found for this email address
                    </div>
                `;
            }
        } else {
            html += `
                <div class="result-item">
                    <strong>📧 Email Analysis:</strong><br>
                    <span class="status-indicator status-error"></span>
                    ${emailData && emailData.message ? emailData.message : 'Failed to analyze email'}
                </div>
            `;
        }

        // Display SPF information if available
        if (spfData) {
            const hasRecord = spfData.record ? 'status-success' : 'status-warning';
            
            html += `
                <div class="result-item">
                    <strong>📧 SPF Analysis (${spfData.domain}):</strong><br>
                    <span class="status-indicator ${hasRecord}"></span>
                    <strong>Message:</strong> ${spfData.message || 'N/A'}<br>
                    ${spfData.record ? `<strong>Record:</strong> ${spfData.record}<br>` : ''}
                    ${spfData.details && spfData.details.all_mechanism ? 
                        `<strong>All Mechanism:</strong> ${spfData.details.all_mechanism}<br>` : ''}
                    ${spfData.details && spfData.details.includes && spfData.details.includes.length > 0 ? 
                        `<strong>Includes:</strong> ${spfData.details.includes.slice(0, 2).join(', ')}${spfData.details.includes.length > 2 ? '...' : ''}<br>` : ''}
                </div>
            `;
        }

        content.innerHTML = html || '<p>No email data available</p>';
        
        // Show security assessment for email
        displayEmailSecurityAssessment(emailData, spfData);
    }

    function displayLeakCheckResults(data) {
        resultsSection.style.display = 'block';
        domainResults.style.display = 'none';
        emailResults.style.display = 'block';
        securityResults.style.display = 'block';
        
        const content = document.getElementById('emailContent');
        let html = '';
        
        if (data && data.status === 'success') {
            if (data.found && data.found.length > 0) {
                html += `
                    <div class="result-item">
                        <strong>⚠️ Breach Detection:</strong><br>
                        <span class="status-indicator status-error"></span>
                        <strong>Email found in ${data.found.length} breach(es)</strong><br>
                        ${data.found.slice(0, 5).map(breach => 
                            `• ${breach.name || breach.source || 'Unknown source'} (${breach.date || 'Unknown date'})`
                        ).join('<br>')}
                        ${data.found.length > 5 ? `<br>... and ${data.found.length - 5} more` : ''}
                    </div>
                `;
            } else {
                html += `
                    <div class="result-item">
                        <strong>✅ Breach Detection:</strong><br>
                        <span class="status-indicator status-success"></span>
                        No breaches found for this email address
                    </div>
                `;
            }
        } else {
            html += `
                <div class="result-item">
                    <strong>📧 Email Analysis:</strong><br>
                    <span class="status-indicator status-error"></span>
                    ${data && data.message ? data.message : 'Failed to analyze email'}
                </div>
            `;
        }
        
        content.innerHTML = html;
        
        // Show security assessment for email
        displayEmailSecurityAssessment(data);
    }

    function displayEmailSecurityAssessment(emailData, spfData = null) {
        const content = document.getElementById('securityContent');
        let html = '';
        
        let riskScore = 0;
        let threats = [];
        
        // Assess email breach risk
        if (emailData && emailData.status === 'success') {
            if (emailData.found && emailData.breach_count > 0) {
                threats.push(`Email found in ${emailData.breach_count} breach(es)`);
                riskScore += Math.min(emailData.breach_count * 15, 60); // Cap breach risk at 60
            } else {
                riskScore += 0; // No breach risk
            }
        } else {
            threats.push('Email analysis failed');
            riskScore += 30;
        }
        
        // Assess SPF risk
        if (spfData) {
            if (spfData.record) {
                // SPF record exists, reduces overall risk
                riskScore = Math.max(0, riskScore - 10);
                if (spfData.details && spfData.details.all_mechanism === '+all') {
                    threats.push('SPF allows all senders');
                    riskScore += 15;
                }
            } else {
                threats.push('No SPF record found');
                riskScore += 10;
            }
        }
        
        const riskLevel = riskScore > 60 ? 'High' : riskScore > 30 ? 'Medium' : 'Low';
        const riskClass = riskScore > 60 ? 'status-error' : riskScore > 30 ? 'status-warning' : 'status-success';
        
        html += `
            <div class="result-item">
                <strong>📊 Email Security Assessment:</strong><br>
                <span class="status-indicator ${riskClass}"></span>
                <strong>Risk Level:</strong> ${riskLevel} (${riskScore}/100)<br>
                ${threats.length > 0 ? `<strong>Issues:</strong> ${threats.join(', ')}` : '<strong>Status:</strong> Email appears secure'}
            </div>
        `;
        
        content.innerHTML = html;
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

    function displayLeakCheckResults(data) {
        resultsSection.style.display = 'block';
        domainResults.style.display = 'none';
        emailResults.style.display = 'block';
        securityResults.style.display = 'block';

        // Display LeakCheck email results
        const emailContent = document.getElementById('emailContent');
        let emailHtml = '';

        if (data.status === 'success') {
            const riskColor = data.risk_level === 'high' ? 'error' : 
                             data.risk_level === 'medium' ? 'warning' : 'success';
            
            emailHtml += `
                <div class="result-item">
                    <strong>LeakCheck Breach Detection:</strong><br>
                    <span class="status-indicator status-${riskColor}"></span>
                    Email: ${data.email}<br>
                    Found in ${data.breach_count} breach(es)<br>
                    Risk Level: ${data.risk_level.toUpperCase()}
                </div>
            `;

            if (data.sources && data.sources.length > 0) {
                emailHtml += `
                    <div class="result-item">
                        <strong>Breach Sources (showing ${Math.min(data.sources.length, 10)} of ${data.total_sources}):</strong><br>
                        ${data.sources.slice(0, 10).map(source => 
                            `<span class="status-indicator status-warning"></span>${source}`
                        ).join('<br>')}
                    </div>
                `;
            }
        } else if (data.status === 'error') {
            emailHtml = `
                <div class="result-item">
                    <span class="status-indicator status-error"></span>
                    Error: ${data.error || 'Failed to check email against LeakCheck database'}
                </div>
            `;
        }

        emailContent.innerHTML = emailHtml;

        // Display security assessment
        const securityContent = document.getElementById('securityContent');
        let securityHtml = '';

        if (data.status === 'success') {
            const riskColor = data.risk_level === 'high' ? 'error' : 
                             data.risk_level === 'medium' ? 'warning' : 'success';
            
            securityHtml += `
                <div class="result-item">
                    <strong>Email Security Assessment:</strong><br>
                    <span class="status-indicator status-${riskColor}"></span>
                    ${data.risk_message}<br>
                    Status: ${data.message}
                </div>
            `;
        }

        securityContent.innerHTML = securityHtml || '<p>Security assessment completed</p>';
    }

    function displayCombinedResults(domainData, emailData) {
        resultsSection.style.display = 'block';
        domainResults.style.display = 'block';
        emailResults.style.display = 'block';
        securityResults.style.display = 'block';

        // Display domain results (reuse existing function logic)
        const domainContent = document.getElementById('domainContent');
        let domainHtml = '';

        if (domainData.status === 'success') {
            domainHtml += `
                <div class="result-item">
                    <strong>Domain Information:</strong><br>
                    <span class="status-indicator status-success"></span>Domain: ${domainData.domain}<br>
                    ${domainData.registrar ? `Registrar: ${domainData.registrar}<br>` : ''}
                    ${domainData.creation_date ? `Created: ${domainData.creation_date}<br>` : ''}
                    ${domainData.expiration_date ? `Expires: ${domainData.expiration_date}<br>` : ''}
                </div>
            `;
        }
        domainContent.innerHTML = domainHtml;

        // Display email results (reuse LeakCheck logic)
        const emailContent = document.getElementById('emailContent');
        let emailHtml = '';

        if (emailData.status === 'success') {
            const riskColor = emailData.risk_level === 'high' ? 'error' : 
                             emailData.risk_level === 'medium' ? 'warning' : 'success';
            
            emailHtml += `
                <div class="result-item">
                    <strong>LeakCheck Breach Detection:</strong><br>
                    <span class="status-indicator status-${riskColor}"></span>
                    Email: ${emailData.email}<br>
                    Found in ${emailData.breach_count} breach(es)<br>
                    Risk Level: ${emailData.risk_level.toUpperCase()}
                </div>
            `;
        }
        emailContent.innerHTML = emailHtml;

        // Combined security assessment
        const securityContent = document.getElementById('securityContent');
        let securityHtml = '';

        // Domain security
        if (domainData.security_assessment) {
            const assessment = domainData.security_assessment;
            const riskColor = assessment.risk_level === 'high' ? 'error' : 
                             assessment.risk_level === 'medium' ? 'warning' : 'success';
            
            securityHtml += `
                <div class="result-item">
                    <strong>Domain Security:</strong><br>
                    <span class="status-indicator status-${riskColor}"></span>
                    Risk Level: ${assessment.risk_level.toUpperCase()}<br>
                    ${assessment.days_until_expiry !== null ? 
                        `Days Until Expiry: ${assessment.days_until_expiry}<br>` : ''}
                </div>
            `;
        }

        // Email security
        if (emailData.status === 'success') {
            const riskColor = emailData.risk_level === 'high' ? 'error' : 
                             emailData.risk_level === 'medium' ? 'warning' : 'success';
            
            securityHtml += `
                <div class="result-item">
                    <strong>Email Security:</strong><br>
                    <span class="status-indicator status-${riskColor}"></span>
                    ${emailData.risk_message}
                </div>
            `;
        }

        securityContent.innerHTML = securityHtml || '<p>Combined security assessment completed</p>';
    }

    // Initialize form state
    scanType.dispatchEvent(new Event('change'));
});
