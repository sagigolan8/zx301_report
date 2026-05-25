// ============================================================================
// VULNER ZX301 - Interactive Report Dashboard
// Handles: JSON parsing, table rendering, column filtering, sorting
// ============================================================================

let scanData = [];      // Parsed scan data from the injected JSON
let flatRows = [];      // Flattened array of rows for the table
let currentSort = { col: -1, asc: true };  // Track current sort state

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', function() {

    // 1. Load JSON data injected by the bash script into the vulnerData tag
    try {
        var rawData = document.getElementById('vulnerData').textContent.trim();
        if (rawData && rawData !== '[]') {
            scanData = JSON.parse(rawData);
        }
    } catch(e) {
        console.error("Failed to parse JSON payload:", e.message);
    }

    // 2. If no data was injected, show an empty state (no dummy data)
    if (!scanData || scanData.length === 0) {
        document.getElementById('tableBody').innerHTML =
            '<tr><td colspan="8" style="text-align:center; padding:40px; color:#94a3b8;">No scan data available. Run the VULNER script to generate results.</td></tr>';
        return;
    }

    // 3. Flatten the data: one row per port entry, with host IP and credentials attached
    flatRows = [];
    scanData.forEach(function(host) {
        // Build a credentials lookup for this host
        var hostCreds = {};
        if (host.credentials && host.credentials.length > 0) {
            host.credentials.forEach(function(c) {
                hostCreds[c.service] = c.user + ' : ' + c.pass;
            });
        }

        if (host.ports && host.ports.length > 0) {
            host.ports.forEach(function(p) {
                flatRows.push({
                    ip: host.ip,
                    port: p.port,
                    protocol: p.protocol || 'tcp',
                    state: p.state || 'open',
                    service: p.service || 'Unknown',
                    version: p.version || 'Unknown',
                    severity: p.severity || 'low',
                    cves: p.cves || [],
                    cred: hostCreds[p.service] || ''
                });
            });
        }
    });

    // 4. Populate filter dropdowns based on actual data
    populateFilters();

    // 5. Calculate and display statistics
    calculateStats();

    // 6. Render the full table
    renderTable(flatRows);
});

// ============================================================================
// STATISTICS
// ============================================================================
function calculateStats() {
    var uniqueHosts = {};
    var totalPorts = 0;
    var totalCreds = 0;
    var vulnPorts = 0;

    scanData.forEach(function(host) {
        uniqueHosts[host.ip] = true;
        totalPorts += (host.ports || []).length;
        totalCreds += (host.credentials || []).length;
        if (host.ports) {
            host.ports.forEach(function(p) {
                if (p.severity === 'high' || p.severity === 'medium') {
                    vulnPorts++;
                }
            });
        }
    });

    document.getElementById('totalHosts').innerText = Object.keys(uniqueHosts).length;
    document.getElementById('totalPorts').innerText = totalPorts;
    document.getElementById('totalVulns').innerText = vulnPorts;
    document.getElementById('totalCreds').innerText = totalCreds;
}

// ============================================================================
// FILTER DROPDOWNS
// ============================================================================
function populateFilters() {
    var ips = {};
    var services = {};
    var states = {};

    flatRows.forEach(function(r) {
        ips[r.ip] = true;
        services[r.service] = true;
        states[r.state] = true;
    });

    var ipSelect = document.getElementById('filterIP');
    Object.keys(ips).sort().forEach(function(ip) {
        var opt = document.createElement('option');
        opt.value = ip;
        opt.textContent = ip;
        ipSelect.appendChild(opt);
    });

    var svcSelect = document.getElementById('filterService');
    Object.keys(services).sort().forEach(function(svc) {
        var opt = document.createElement('option');
        opt.value = svc;
        opt.textContent = svc;
        svcSelect.appendChild(opt);
    });

    var stateSelect = document.getElementById('filterState');
    Object.keys(states).sort().forEach(function(st) {
        var opt = document.createElement('option');
        opt.value = st;
        opt.textContent = st;
        stateSelect.appendChild(opt);
    });
}

// ============================================================================
// FILTERING
// ============================================================================
function applyFilters() {
    var fIP = document.getElementById('filterIP').value;
    var fService = document.getElementById('filterService').value;
    var fState = document.getElementById('filterState').value;
    var fSeverity = document.getElementById('filterSeverity').value;
    var fProtocol = document.getElementById('filterProtocol').value;

    var filtered = flatRows.filter(function(r) {
        if (fIP !== 'all' && r.ip !== fIP) return false;
        if (fService !== 'all' && r.service !== fService) return false;
        if (fState !== 'all' && r.state !== fState) return false;
        if (fSeverity !== 'all' && r.severity !== fSeverity) return false;
        if (fProtocol !== 'all' && r.protocol !== fProtocol) return false;
        return true;
    });

    renderTable(filtered);
}

function resetFilters() {
    document.getElementById('filterIP').value = 'all';
    document.getElementById('filterService').value = 'all';
    document.getElementById('filterState').value = 'all';
    document.getElementById('filterSeverity').value = 'all';
    document.getElementById('filterProtocol').value = 'all';
    renderTable(flatRows);
}

// ============================================================================
// SORTING
// ============================================================================
function sortTable(colIndex) {
    // Toggle sort direction if clicking same column
    if (currentSort.col === colIndex) {
        currentSort.asc = !currentSort.asc;
    } else {
        currentSort.col = colIndex;
        currentSort.asc = true;
    }

    // Map column index to row property
    var keys = ['ip', 'port', 'protocol', 'state', 'service', 'version', 'severity', 'cred'];
    var key = keys[colIndex];

    // Get currently visible rows from the table
    var visibleRows = getVisibleRows();

    visibleRows.sort(function(a, b) {
        var valA = a[key];
        var valB = b[key];

        // Numeric sort for port numbers
        if (key === 'port') {
            valA = parseInt(valA) || 0;
            valB = parseInt(valB) || 0;
        }

        if (valA < valB) return currentSort.asc ? -1 : 1;
        if (valA > valB) return currentSort.asc ? 1 : -1;
        return 0;
    });

    renderTable(visibleRows);

    // Update sort indicators in header
    var ths = document.querySelectorAll('.results-table th');
    ths.forEach(function(th, i) {
        th.classList.remove('sort-asc', 'sort-desc');
        if (i === colIndex) {
            th.classList.add(currentSort.asc ? 'sort-asc' : 'sort-desc');
        }
    });
}

function getVisibleRows() {
    // Re-filter to get the current visible set
    var fIP = document.getElementById('filterIP').value;
    var fService = document.getElementById('filterService').value;
    var fState = document.getElementById('filterState').value;
    var fSeverity = document.getElementById('filterSeverity').value;
    var fProtocol = document.getElementById('filterProtocol').value;

    return flatRows.filter(function(r) {
        if (fIP !== 'all' && r.ip !== fIP) return false;
        if (fService !== 'all' && r.service !== fService) return false;
        if (fState !== 'all' && r.state !== fState) return false;
        if (fSeverity !== 'all' && r.severity !== fSeverity) return false;
        if (fProtocol !== 'all' && r.protocol !== fProtocol) return false;
        return true;
    });
}

// ============================================================================
// TABLE RENDERING
// ============================================================================
function renderTable(rows) {
    var tbody = document.getElementById('tableBody');
    tbody.innerHTML = '';

    if (rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:30px; color:#94a3b8;">No results match the current filters.</td></tr>';
        return;
    }

    rows.forEach(function(r) {
        var tr = document.createElement('tr');

        // State CSS class
        var stateClass = 'state-' + r.state;

        // Severity badge
        var sevHtml = '<span class="severity-badge severity-' + r.severity + '">' + r.severity + '</span>';

        // Credentials cell
        var credHtml = r.cred ? '<span class="cred-badge">' + escapeHtml(r.cred) + '</span>' : '<span style="color:#475569">—</span>';

        // Remediation cell (CVE links)
        var cveHtml = '<span style="color:#475569">—</span>';
        if (r.cves && r.cves.length > 0) {
            cveHtml = r.cves.map(function(cve) {
                return '<a href="https://nvd.nist.gov/vuln/detail/' + escapeHtml(cve) + '" target="_blank" class="cve-link">' + escapeHtml(cve) + '</a>';
            }).join(' ');
        }

        tr.innerHTML =
            '<td>' + escapeHtml(r.ip) + '</td>' +
            '<td><span class="port-num">' + escapeHtml(r.port) + '</span></td>' +
            '<td>' + escapeHtml(r.protocol) + '</td>' +
            '<td><span class="' + stateClass + '">' + escapeHtml(r.state) + '</span></td>' +
            '<td>' + escapeHtml(r.service) + '</td>' +
            '<td>' + escapeHtml(r.version) + '</td>' +
            '<td>' + sevHtml + '</td>' +
            '<td>' + credHtml + '</td>' +
            '<td>' + cveHtml + '</td>';

        tbody.appendChild(tr);
    });
}

// Prevent XSS by escaping HTML characters
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
