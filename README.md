# VULNER ZX301 Report UI

This repository holds the static frontend assets (HTML, CSS, JS) for the `PERES25A.s14.ZX301.sh` automated penetration testing script.

## How It Works

The bash script runs network scans and brute forces credentials. Instead of just dumping raw text files, it constructs a JSON payload containing all findings (Hosts, Ports, CVEs, Credentials).

The script then uses `curl` or `wget` to download `index.html`, `style.css`, and `script.js` from this repository. It injects the JSON payload directly into the `index.html` file and opens it in a local web browser, providing a beautiful, filterable dashboard of the vulnerabilities!

### Files
- `index.html`: The structural template.
- `style.css`: The styling (Dark mode, Hacker-themed).
- `script.js`: Handles JSON parsing, chart rendering, and filtering logic.
