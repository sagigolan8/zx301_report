# VULNER ZX301 Report UI

This repository holds the static frontend assets (HTML, CSS, JS) for the `PERES25A.s14.ZX301.sh` automated penetration testing script.

## How It Works

The bash script runs network scans, discovers vulnerabilities, and brute forces credentials. It then compiles all results into a structured JSON payload containing:
- **Host IPs** discovered on the network
- **Port details**: port number, protocol, state, service name, and version
- **Severity ratings**: high, medium, low based on port risk assessment
- **Cracked credentials**: service, username, and password pairs

The script uses `curl` or `wget` to download `index.html`, `style.css`, and `script.js` from this repository. It then injects the JSON payload directly into `index.html` and opens it in the browser.

## Features

- **Sortable Table**: Click any column header (Host, Port, Protocol, State, Service, Version, Severity) to sort ascending/descending
- **Per-Column Filters**: Filter by Host IP, Service, State, Severity, or Protocol independently
- **Statistics Dashboard**: Live cards showing Total Hosts, Open Ports, Vulnerabilities, and Weak Credentials
- **Remediation Links**: Automatically extracts CVE IDs from Nmap XML outputs and renders them as clickable links to the NVD database (e.g. CVE-2011-2523)
- **Reset Filters**: One-click button to clear all active filters
- **XSS Safe**: All data is HTML-escaped before rendering
- **No External Libraries**: Pure HTML, CSS, and JavaScript — no dependencies

### Files
- `index.html`: The table-based dashboard template
- `style.css`: Dark-themed professional styling
- `script.js`: Handles JSON parsing, table rendering, filtering, and sorting
