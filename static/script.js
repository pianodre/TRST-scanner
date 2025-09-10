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
    const domainContainer = document.getElementById('domainContainer');
    const emailContainer = document.getElementById('emailContainer');
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
            domainContainer.style.display = 'block';
            emailContainer.style.display = 'none';
            domainInput.required = true;
            emailInput.required = false;
        } else if (type === 'email') {
            domainContainer.style.display = 'none';
            emailContainer.style.display = 'block';
            domainInput.required = false;
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

        // WHOIS Status Card
        const whoisStatus = evaluateWhoisStatus(whoisData);
        html += createStatusCard('🏢', 'Domain Registration', whoisStatus, 
            getWhoisSummary(whoisData), getWhoisTechnicalDetails(whoisData));

        // DMARC Status Card
        const dmarcStatus = evaluateDmarcStatus(dmarcData);
        html += createStatusCard('🔒', 'DMARC Policy', dmarcStatus, 
            getDmarcSummary(dmarcData), getDmarcTechnicalDetails(dmarcData));

        // SPF Status Card
        const spfStatus = evaluateSpfStatus(spfData);
        html += createStatusCard('📧', 'SPF Policy', spfStatus, 
            getSpfSummary(spfData), getSpfTechnicalDetails(spfData));

        content.innerHTML = html;
        
        // Add click handlers for expand buttons
        addExpandHandlers();
        
        // Show security assessment
        displaySecurityAssessment(whoisData, dmarcData, spfData);
    }


    // Helper functions for the new visual design
    function createStatusCard(icon, title, status, summary, technicalDetails) {
        const cardId = `card-${Math.random().toString(36).substr(2, 9)}`;
        return `
            <div class="status-card">
                <div class="status-header">
                    <div class="status-title">
                        <span class="status-icon">${icon}</span>
                        ${title}
                    </div>
                    <div class="status-visual">
                        <span class="status-badge status-${status.level}">${status.text}</span>
                        <button class="expand-btn" data-target="${cardId}">Details</button>
                    </div>
                </div>
                <div class="summary-text">${summary}</div>
                <div class="technical-details" id="${cardId}">
                    ${technicalDetails}
                </div>
            </div>
        `;
    }

    function evaluateWhoisStatus(whoisData) {
        if (!whoisData || whoisData.status !== 'success') {
            return { level: 'bad', text: 'Failed' };
        }
        
        if (whoisData.security_assessment) {
            const daysUntilExpiry = whoisData.security_assessment.days_until_expiry;
            if (daysUntilExpiry !== null) {
                if (daysUntilExpiry < 30) return { level: 'bad', text: 'Expires Soon' };
                if (daysUntilExpiry < 90) return { level: 'good', text: 'Active' };
                return { level: 'great', text: 'Secure' };
            }
        }
        
        return { level: 'good', text: 'Active' };
    }

    function evaluateDmarcStatus(dmarcData) {
        if (!dmarcData || !dmarcData.record) {
            return { level: 'bad', text: 'Not Found' };
        }
        
        // Check if policy exists in details, if not try to parse from record
        let policy = dmarcData.details?.policy;
        
        if (!policy && dmarcData.record) {
            // Try to extract policy from the record directly
            const policyMatch = dmarcData.record.match(/p=([^;"\s]+)/i);
            if (policyMatch) {
                policy = policyMatch[1].toLowerCase();
            }
        }
        
        if (policy) {
            if (policy === 'reject') return { level: 'great', text: 'Strict' };
            if (policy === 'quarantine') return { level: 'good', text: 'Moderate' };
            if (policy === 'none') return { level: 'bad', text: 'Monitoring' };
        }
        
        return { level: 'good', text: 'Configured' };
    }

    function evaluateSpfStatus(spfData) {
        if (!spfData || !spfData.record) {
            return { level: 'bad', text: 'Not Found' };
        }
        
        // Check for redirect mechanism (like Gmail uses) - this is secure
        if (spfData.record.includes('redirect=')) {
            return { level: 'great', text: 'Secure' };
        }
        
        // Check if all_mechanism exists in details, if not try to parse from record
        let allMechanism = spfData.details?.all_mechanism;
        
        if (!allMechanism && spfData.record) {
            // Try to extract from the record directly
            const recordMatch = spfData.record.match(/([~+-]?)all\b/);
            if (recordMatch) {
                allMechanism = (recordMatch[1] || '+') + 'all';
            }
        }
        
        if (allMechanism) {
            if (allMechanism === '-all') return { level: 'great', text: 'Strict' };
            if (allMechanism === '~all') return { level: 'good', text: 'Moderate' };
            if (allMechanism === '+all') return { level: 'bad', text: 'Permissive' };
        }
        
        return { level: 'good', text: 'Configured' };
    }

    function getWhoisSummary(whoisData) {
        if (!whoisData || whoisData.status !== 'success') {
            return 'Unable to retrieve domain registration information.';
        }
        
        const registrar = whoisData.registrar || 'Private/Protected registrar';
        const expires = whoisData.expiration_date || 'Protected expiration date';
        return `Domain registered with ${registrar}. Expires: ${expires}`;
    }

    function getDmarcSummary(dmarcData) {
        if (!dmarcData || !dmarcData.record) {
            return 'No DMARC policy found. Email spoofing protection is not configured.';
        }
        
        // Check if policy exists in details, if not try to parse from record
        let policy = dmarcData.details?.policy;
        
        if (!policy && dmarcData.record) {
            // Try to extract policy from the record directly
            const policyMatch = dmarcData.record.match(/p=([^;"\s]+)/i);
            if (policyMatch) {
                policy = policyMatch[1].toLowerCase();
            } else {
                policy = 'unknown';
            }
        }
        
        return `DMARC policy set to "${policy || 'unknown'}". Email authentication is configured.`;
    }

    function getSpfSummary(spfData) {
        if (!spfData || !spfData.record) {
            return 'No SPF record found. Sender authentication is not configured.';
        }
        
        // Check for redirect mechanism first
        if (spfData.record.includes('redirect=')) {
            const redirectMatch = spfData.record.match(/redirect=([^\s]+)/);
            const redirectDomain = redirectMatch ? redirectMatch[1] : 'external domain';
            return `SPF policy redirects to ${redirectDomain} for authorization rules.`;
        }
        
        // Check if all_mechanism exists in details, if not try to parse from record
        let mechanism = spfData.details?.all_mechanism;
        
        if (!mechanism && spfData.record) {
            // Try to extract from the record directly
            const recordMatch = spfData.record.match(/([~+-]?)all\b/);
            if (recordMatch) {
                mechanism = (recordMatch[1] || '+') + 'all';
            } else {
                mechanism = 'configured';
            }
        }
        
        const includeCount = spfData.details?.includes?.length || 0;
        return `SPF policy "${mechanism || 'configured'}" with ${includeCount} authorized mail services.`;
    }

    function getWhoisTechnicalDetails(whoisData) {
        if (!whoisData || whoisData.status !== 'success') {
            return `<strong>Error:</strong> ${whoisData?.error || 'Failed to retrieve WHOIS data'}`;
        }
        
        return `
            <strong>Domain:</strong> ${whoisData.domain || 'N/A'}<br>
            <strong>Registrar:</strong> ${whoisData.registrar || 'Privacy Protected'}<br>
            <strong>Created:</strong> ${whoisData.creation_date || 'Privacy Protected'}<br>
            <strong>Expires:</strong> ${whoisData.expiration_date || 'Privacy Protected'}<br>
            <strong>Updated:</strong> ${whoisData.updated_date || 'Privacy Protected'}<br>
            ${whoisData.nameservers && whoisData.nameservers.length > 0 ? 
                `<strong>Nameservers:</strong> ${whoisData.nameservers.join(', ')}` : '<strong>Nameservers:</strong> Privacy Protected'}
        `;
    }

    function getDmarcTechnicalDetails(dmarcData) {
        if (!dmarcData || !dmarcData.record) {
            return `<strong>Message:</strong> ${dmarcData?.message || 'No DMARC record found'}`;
        }
        
        return `
            <strong>Record:</strong> ${dmarcData.record}<br>
            <strong>Policy:</strong> ${dmarcData.details?.policy || 'N/A'}<br>
            <strong>Percentage:</strong> ${dmarcData.details?.percentage || 'N/A'}%<br>
            <strong>Subdomain Policy:</strong> ${dmarcData.details?.subdomain_policy || 'N/A'}<br>
            <strong>Reporting URI:</strong> ${dmarcData.details?.reporting_uri || 'Not configured'}<br>
            <strong>Forensic URI:</strong> ${dmarcData.details?.forensic_uri || 'Not configured'}
        `;
    }

    function getSpfTechnicalDetails(spfData) {
        if (!spfData || !spfData.record) {
            return `<strong>Message:</strong> ${spfData?.message || 'No SPF record found'}`;
        }
        
        return `
            <strong>Record:</strong> ${spfData.record}<br>
            <strong>All Mechanism:</strong> ${spfData.details?.all_mechanism || 'N/A'}<br>
            <strong>Includes:</strong> ${spfData.details?.includes?.join(', ') || 'None'}<br>
            <strong>IP4 Addresses:</strong> ${spfData.details?.ip4_addresses?.join(', ') || 'None'}<br>
            <strong>IP6 Addresses:</strong> ${spfData.details?.ip6_addresses?.join(', ') || 'None'}<br>
            <strong>MX Records:</strong> ${spfData.details?.mx_records?.join(', ') || 'None'}
        `;
    }

    function evaluateBreachStatus(emailData) {
        if (!emailData || emailData.status !== 'success') {
            return { level: 'bad', text: 'Failed' };
        }
        
        if (emailData.found && emailData.breach_count > 0) {
            if (emailData.breach_count >= 2) return { level: 'bad', text: 'High Risk' };
            if (emailData.breach_count === 1) return { level: 'good', text: 'Medium Risk' };
        }
        
        return { level: 'great', text: 'Clean' };
    }

    function getBreachSummary(emailData) {
        if (!emailData || emailData.status !== 'success') {
            return 'Unable to check email against breach databases.';
        }
        
        if (emailData.found && emailData.breach_count > 0) {
            return `Email found in ${emailData.breach_count} data breach(es). Immediate action recommended.`;
        }
        
        return 'No breaches found. Email appears secure in known databases.';
    }

    function getBreachTechnicalDetails(emailData) {
        if (!emailData || emailData.status !== 'success') {
            return `<strong>Error:</strong> ${emailData?.message || 'Failed to analyze email'}`;
        }
        
        if (emailData.found && emailData.breach_count > 0) {
            let details = `<strong>Breach Count:</strong> ${emailData.breach_count}<br>`;
            
            if (emailData.sources && emailData.sources.length > 0) {
                details += `<strong>Breach Sources:</strong><br>`;
                emailData.sources.slice(0, 10).forEach(source => {
                    details += `• ${source}<br>`;
                });
                if (emailData.sources.length > 10) {
                    details += `... and ${emailData.sources.length - 10} more<br>`;
                }
            }
            
            return details;
        }
        
        return `<strong>Status:</strong> Clean - No breaches detected<br><strong>Databases Checked:</strong> LeakCheck`;
    }

    function addExpandHandlers() {
        document.querySelectorAll('.expand-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const targetId = this.getAttribute('data-target');
                const details = document.getElementById(targetId);
                
                if (details.classList.contains('expanded')) {
                    details.classList.remove('expanded');
                    this.textContent = 'Details';
                    this.classList.remove('expanded');
                } else {
                    details.classList.add('expanded');
                    this.textContent = 'Hide';
                    this.classList.add('expanded');
                }
            });
        });
    }

    // Function to display security assessment for domain-only scans
    function displaySecurityAssessment(whoisData, dmarcData, spfData) {
        const content = document.getElementById('securityContent');
        
        // Start with base score of 1
        let riskScore10 = 1;
        let threats = [];
        
        // Assess Domain Registration (WHOIS) risk
        const whoisStatus = evaluateWhoisStatus(whoisData);
        if (whoisStatus.level === 'bad') {
            riskScore10 += 2;
            threats.push('Domain registration issues detected');
        } else if (whoisStatus.level === 'good') {
            riskScore10 += 1;
            threats.push('Domain expires within 90 days');
        }
        // Green WHOIS = add 0
        
        // Assess DMARC risk
        const dmarcStatus = evaluateDmarcStatus(dmarcData);
        if (dmarcStatus.level === 'bad') {
            riskScore10 += 1;
            threats.push('No DMARC policy - vulnerable to email spoofing');
        }
        // Blue/Green DMARC = add 0
        
        // Assess SPF risk
        const spfStatus = evaluateSpfStatus(spfData);
        if (spfStatus.level === 'bad') {
            riskScore10 += 4;
            threats.push('No SPF record or permissive policy');
        } else if (spfStatus.level === 'good') {
            riskScore10 += 1;
            threats.push('SPF policy could be stricter');
        }
        // Green SPF = add 0
        
        // Force 10/10 if all three components are red
        if (whoisStatus.level === 'bad' && dmarcStatus.level === 'bad' && spfStatus.level === 'bad') {
            riskScore10 = 10;
            threats.push('All security components failed - maximum risk');
        } else {
            // Cap at 10 and ensure minimum of 1
            riskScore10 = Math.max(1, Math.min(10, riskScore10));
        }
        
        let riskLevel = 'Low Risk';
        if (riskScore10 >= 7) {
            riskLevel = 'High Risk';
        } else if (riskScore10 >= 4) {
            riskLevel = 'Medium Risk';
        }
        
        // Create circular progress meter
        let html = `
            <div class="risk-meter">
                <div class="circular-progress" style="background: conic-gradient(
                    from 0deg,
                    ${riskScore10 <= 3 ? '#4CAF50' : riskScore10 <= 6 ? '#00c3f5' : '#ff4444'} 0deg ${(riskScore10 / 10) * 360}deg,
                    #333 ${(riskScore10 / 10) * 360}deg 360deg
                );">
                    <div class="progress-content">
                        <div class="progress-score">${riskScore10}</div>
                        <div class="progress-label">of 10</div>
                    </div>
                </div>
                <div class="risk-meter-description">
                    <strong>${riskLevel}</strong><br>
        `;
        
        if (threats.length > 0) {
            html += 'Security concerns identified:<br>';
            threats.forEach(threat => {
                html += `• ${threat}<br>`;
            });
        } else {
            html += '✅ No significant security threats detected. Domain appears well-configured.';
        }
        
        html += `
                </div>
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

        // Breach Detection Status Card
        const breachStatus = evaluateBreachStatus(emailData);
        html += createStatusCard('🔍', 'Breach Detection', breachStatus, 
            getBreachSummary(emailData), getBreachTechnicalDetails(emailData));

        // SPF Status Card (if available)
        if (spfData) {
            const spfStatus = evaluateSpfStatus(spfData);
            html += createStatusCard('📧', 'SPF Policy', spfStatus, 
                getSpfSummary(spfData), getSpfTechnicalDetails(spfData));
        }

        content.innerHTML = html;
        
        // Add click handlers for expand buttons
        addExpandHandlers();
        
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
        
        let riskScore = 0;
        let threats = [];
        let forceHighRisk = false;
        
        // Check if breach detection is red (2+ breaches)
        const breachStatus = evaluateBreachStatus(emailData);
        if (breachStatus.level === 'bad') {
            forceHighRisk = true;
        }
        
        // Check if SPF is red
        if (spfData) {
            const spfStatus = evaluateSpfStatus(spfData);
            if (spfStatus.level === 'bad') {
                forceHighRisk = true;
            }
        }
        
        // Start with base score of 1
        let riskScore10 = 1;
        
        // Assess email breach risk - add 2 per breach
        if (emailData && emailData.status === 'success') {
            if (emailData.found && emailData.breach_count > 0) {
                threats.push(`Email found in ${emailData.breach_count} breach(es)`);
                riskScore10 += emailData.breach_count * 2; // Add 2 per breach
            }
        } else {
            threats.push('Email analysis failed');
            riskScore10 += 3; // Add penalty for failed analysis
        }
        
        // Assess SPF risk
        if (spfData) {
            const spfStatus = evaluateSpfStatus(spfData);
            if (spfStatus.level === 'bad') {
                // Red SPF = automatically high risk
                forceHighRisk = true;
                threats.push('No SPF record found or permissive policy');
            } else if (spfStatus.level === 'good') {
                // Blue SPF = add 1
                riskScore10 += 1;
                threats.push('SPF policy could be stricter');
            }
            // Green SPF = add 0 (no penalty)
        } else {
            // No SPF data = add 1
            riskScore10 += 1;
            threats.push('SPF analysis unavailable');
        }
        
        // Cap at 10 and ensure minimum of 1
        riskScore10 = Math.max(1, Math.min(10, riskScore10));
        
        // Force high risk if SPF is red
        if (forceHighRisk) {
            riskScore10 = Math.max(riskScore10, 7); // Force high risk to be at least 7/10
        }
        
        let riskLevel = 'Low Risk';
        if (forceHighRisk || riskScore10 >= 7) {
            riskLevel = 'High Risk';
        } else if (riskScore10 >= 4) {
            riskLevel = 'Medium Risk';
        }
        
        // Create circular progress meter
        let html = `
            <div class="risk-meter">
                <div class="circular-progress" style="background: conic-gradient(
                    from 0deg,
                    ${riskScore10 <= 3 ? '#4CAF50' : riskScore10 <= 6 ? '#00c3f5' : '#ff4444'} 0deg ${(riskScore10 / 10) * 360}deg,
                    #333 ${(riskScore10 / 10) * 360}deg 360deg
                );">
                    <div class="progress-content">
                        <div class="progress-score">${riskScore10}</div>
                        <div class="progress-label">of 10</div>
                    </div>
                </div>
                <div class="risk-meter-description">
                    <strong>${riskLevel}</strong><br>
        `;
        
        if (threats.length > 0) {
            html += 'Security concerns identified:<br>';
            threats.forEach(threat => {
                html += `• ${threat}<br>`;
            });
        } else {
            html += '✅ No significant security threats detected. Email appears secure.';
        }
        
        html += `
                </div>
            </div>
        `;
        
        content.innerHTML = html;
    }


    function displayPlaceholderResults(scanType) {
        resultsSection.style.display = 'block';
        domainResults.style.display = 'none';
        emailResults.style.display = 'none';
        securityResults.style.display = 'block';
        
        let message = '';
        if (scanType === 'email') {
            message = 'Email scanning coming soon! Will include LeakCheck breach detection.';
        }
        
        document.getElementById('securityContent').innerHTML = `
            <div style="color: #00c3f5; font-weight: bold;">
                <span class="status-indicator status-info"></span>
                ${message}
            </div>
        `;
    }




    // Initialize form state
    scanType.dispatchEvent(new Event('change'));
});
