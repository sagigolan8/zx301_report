document.addEventListener('DOMContentLoaded', () => {
    let scanData = [];
    
    // Attempt to load data injected by the bash script
    try {
        const rawData = document.getElementById('vulnerData').textContent;
        if(rawData.trim() !== '[]') {
            scanData = JSON.parse(rawData);
        }
    } catch(e) {
        console.error("No valid JSON payload found.");
    }

    // Dummy data for preview if no actual data is present
    if(scanData.length === 0) {
        scanData = [
            {
                ip: "192.168.1.105",
                ports: [
                    { port: "21", protocol: "tcp", service: "vsftpd 2.3.4", cves: ["CVE-2011-2523"], severity: "critical" },
                    { port: "22", protocol: "tcp", service: "OpenSSH 7.2p2", cves: [], severity: "low" },
                    { port: "80", protocol: "tcp", service: "Apache httpd 2.4.49", cves: ["CVE-2021-41773"], severity: "high" }
                ],
                credentials: [
                    { service: "ftp", user: "anonymous", pass: "" },
                    { service: "ssh", user: "admin", pass: "password123" }
                ]
            }
        ];
    }

    renderDashboard(scanData);
});

function calculateStats(data) {
    let totalPorts = 0;
    let totalVulns = 0;
    let totalCreds = 0;

    data.forEach(host => {
        totalPorts += (host.ports || []).length;
        if(host.ports) {
            host.ports.forEach(p => {
                totalVulns += (p.cves || []).length;
            });
        }
        totalCreds += (host.credentials || []).length;
    });

    document.getElementById('totalHosts').innerText = data.length;
    document.getElementById('totalPorts').innerText = totalPorts;
    document.getElementById('totalVulns').innerText = totalVulns;
    document.getElementById('totalCreds').innerText = totalCreds;
}

function renderDashboard(data) {
    calculateStats(data);
    const container = document.getElementById('hostsList');
    container.innerHTML = '';

    if (data.length === 0) {
        container.innerHTML = '<p>No hosts found matching the criteria.</p>';
        return;
    }

    data.forEach(host => {
        const card = document.createElement('div');
        card.className = 'host-card';
        
        let portsHtml = '';
        if(host.ports && host.ports.length > 0) {
            host.ports.forEach(p => {
                let cveHtml = '';
                if(p.cves && p.cves.length > 0) {
                    p.cves.forEach(cve => {
                        cveHtml += `<span class="cve-badge">${cve}</span>`;
                    });
                }
                
                // Remediation Advice generator
                let remediationHtml = '';
                if(p.cves && p.cves.length > 0) {
                    remediationHtml = `<a href="https://nvd.nist.gov/vuln/detail/${p.cves[0]}" target="_blank" class="remediation-link">↳ View Remediation & Details for ${p.cves[0]}</a>`;
                }

                portsHtml += `
                    <div class="port-item" data-severity="${p.severity || 'low'}">
                        <div class="port-number">${p.port}/${p.protocol}</div>
                        <div class="port-details">
                            <div class="service-name">${p.service || 'Unknown Service'}</div>
                            ${cveHtml}
                            ${remediationHtml ? '<br>' + remediationHtml : ''}
                        </div>
                    </div>
                `;
            });
        } else {
            portsHtml = '<p class="text-secondary">No open ports mapped.</p>';
        }

        let credsHtml = '';
        if(host.credentials && host.credentials.length > 0) {
            let credItems = host.credentials.map(c => `<div class="cred-item">[${c.service.toUpperCase()}] ${c.user} : ${c.pass}</div>`).join('');
            credsHtml = `
                <div class="credentials-box">
                    <h4>⚠ Weak Credentials Discovered</h4>
                    ${credItems}
                </div>
            `;
        }

        card.innerHTML = `
            <div class="host-header">
                <div class="host-ip">⯈ ${host.ip}</div>
            </div>
            <div class="host-body">
                <div class="port-list">
                    ${portsHtml}
                </div>
                ${credsHtml}
            </div>
        `;

        // Store data attributes for filtering
        card.setAttribute('data-searchtext', JSON.stringify(host).toLowerCase());
        container.appendChild(card);
    });
}

function filterResults() {
    const searchText = document.getElementById('searchInput').value.toLowerCase();
    const severityFilter = document.getElementById('severityFilter').value;
    const cards = document.querySelectorAll('.host-card');

    cards.forEach(card => {
        const textMatch = card.getAttribute('data-searchtext').includes(searchText);
        let severityMatch = true;

        if (severityFilter !== 'all') {
            const ports = card.querySelectorAll('.port-item');
            let hasSeverity = false;
            ports.forEach(p => {
                const sev = p.getAttribute('data-severity');
                if (severityFilter === 'high' && (sev === 'critical' || sev === 'high')) hasSeverity = true;
                if (severityFilter === 'medium' && sev === 'medium') hasSeverity = true;
                if (severityFilter === 'low' && sev === 'low') hasSeverity = true;
            });
            severityMatch = hasSeverity || (ports.length === 0 && severityFilter === 'low'); // Show empty ones only on low/all
        }

        if (textMatch && severityMatch) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}
