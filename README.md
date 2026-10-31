# SUBMAP

```
  ____  _   _ ____  __  __    _    ____
 / ___|| | | | __ )|  \/  |  / \  |  _ \
 \___ \| | | |  _ \| |\/| | / _ \ | |_) |
  ___) | |_| | |_) | |  | |/ ___ \|  __/
 |____/ \___/|____/|_|  |_/_/   \_\_|

  advanced subdomain discovery & attack surface mapping
  created by Kishore Baskaran (0xk1sh0re)  v1.0.0
```

**SUBMAP** is an advanced, modular, command-line cybersecurity reconnaissance framework for subdomain discovery, DNS intelligence, live host detection, API discovery, JavaScript analysis, information exposure detection, and attack surface mapping.

> ⚠️ **LEGAL DISCLAIMER** — Use SUBMAP only against systems you own or have explicit written authorization to test. Unauthorized scanning is illegal. The author assumes no liability for misuse.

---

## Features

| Module | Capability |
|--------|-----------|
| **Subdomain Discovery** | crt.sh, HackerTarget, AlienVault OTX, URLScan.io, Subfinder, Amass, Findomain, DNS brute-force, recursive, wildcard detection |
| **DNS Intelligence** | A, AAAA, CNAME, MX, NS, TXT, CAA, PTR, wildcard detection |
| **Live Host Detection** | HTTP/HTTPS probing, title, server, redirect chain, response time, CDN detection |
| **Technology Fingerprinting** | Web servers, frameworks, CMS, JS frameworks, CDN providers |
| **TLS Analysis** | Certificate expiry, hostname mismatch, TLS version |
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **Port Discovery** | Naabu (fast), Nmap (detailed), or built-in TCP connect fallback |
| **API Discovery** | REST, GraphQL, OpenAPI/Swagger, Spring Actuator, auth endpoints |
| **JavaScript Analysis** | Endpoint extraction, API route extraction, secret detection (redacted), source map detection |
| **URL Reconnaissance** | Katana crawler, GAU historical URLs, parameter extraction, category classification |
| **Information Exposure** | .env files, .git exposure, backup files, debug pages, directory listings, config files, log files |
| **Risk Classification** | HIGH / MEDIUM / LOW with evidence, confidence, and remediation guidance |
| **Asset Mapping** | Subdomain→IP relationships, API linkage, JSON graph |
| **Reporting** | TXT, JSON, CSV, Markdown, HTML with dark-theme report |
| **SQLite Storage** | Scan history, resume interrupted scans |

---

## Installation

### Requirements

- Python 3.12+
- Linux (Kali, Ubuntu, Debian recommended)
- Git

### Quick Install (recommended)

```bash
# 1. Clone the repo
git clone https://github.com/kishore007447/SUBMAP-CLI.git
cd SUBMAP-CLI

# 2. Run the installer
chmod +x install.sh
./install.sh
```

Restart your terminal then:

```bash
submap --help
submap --version
```

### Manual Install (pip)

```bash
git clone https://github.com/kishore007447/SUBMAP-CLI.git
cd SUBMAP-CLI
pip install -e .
```

### Optional External Tools

Install these for significantly enhanced results:

```bash
# Go tools (requires Go 1.21+)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest

# Kali / Ubuntu packages
sudo apt install amass nmap -y
```

SUBMAP checks for each tool at runtime — all are optional.

---

## Usage

### Basic Scan (passive + live + DNS + TLS + headers)

```bash
submap -d example.com
```

### Save Results

```bash
submap -d example.com -o results/
```

### Full Passive + Active Recon

```bash
submap -d example.com --passive --active --live --dns --tls --headers --tech -o results/
```

### API + JavaScript + Leak Detection

```bash
submap -d example.com --api --js --leaks -o results/
```

### DNS Brute-force with Custom Wordlist

```bash
submap -d example.com --bruteforce --wordlist wordlist.txt
```

### Multiple Domains from File

```bash
submap -l domains.txt -o results/ -t 20 --rate-limit 15
```

### Full Scan (all modules)

```bash
submap -d example.com \
  --passive --active --bruteforce --recursive \
  --live --dns --ports --tech --api --urls --js --leaks --tls --headers \
  -t 20 --rate-limit 10 --timeout 15 \
  -o results/ -v
```

### Silent Output (hostnames only to stdout)

```bash
submap -d example.com --silent
```

### With HTTP Proxy (Burp Suite)

```bash
submap -d example.com --proxy http://127.0.0.1:8080 --api --leaks
```

---

## CLI Flags Reference

### Input / Output

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--domain` | `-d` | Single target domain | — |
| `--list` | `-l` | File containing multiple domains | — |
| `--output` | `-o` | Output directory | — |
| `--save` | `-s` | Save scan output to disk | off |
| `--resume` | | Resume interrupted scan | off |
| `--exclude` | | Comma-separated domains to exclude | — |
| `--include` | | Comma-separated patterns to include | — |

### Discovery

| Flag | Description | Default |
|------|-------------|---------|
| `--passive / --no-passive` | Passive enumeration | **on** |
| `--active` | Active DNS enumeration + external tools | off |
| `--bruteforce` | DNS brute-force | off |
| `--recursive` | Recursive subdomain discovery | off |
| `--wordlist FILE` | Custom wordlist for brute-force | built-in |
| `--resolvers FILE` | Custom DNS resolver list | public resolvers |

### Reconnaissance

| Flag | Description | Default |
|------|-------------|---------|
| `--live / --no-live` | Live host HTTP/HTTPS probing | **on** |
| `--dns / --no-dns` | DNS record enumeration | **on** |
| `--ports` | Port discovery (active — requires authorization) | off |
| `--tech / --no-tech` | Technology fingerprinting | **on** |
| `--api` | API endpoint discovery | off |
| `--urls` | URL collection (Katana + GAU) | off |
| `--js` | JavaScript file analysis | off |
| `--leaks` | Information exposure checks | off |
| `--tls / --no-tls` | TLS certificate analysis | **on** |
| `--headers / --no-headers` | Security header analysis | **on** |
| `--cloud` | Cloud asset identification | off |

### Performance

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--threads N` | `-t` | Concurrent workers | 10 |
| `--timeout N` | | Request timeout (seconds) | 10 |
| `--retries N` | | Retry count per request | 2 |
| `--rate-limit N` | | Requests per second | 30 |
| `--delay N` | | Delay between requests (seconds) | 0.0 |
| `--proxy URL` | | HTTP/HTTPS proxy | — |

### General

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Verbose output |
| `--silent` | | Minimal output (hostnames only) |
| `--version` | | Show version and exit |
| `--help` | | Show help and exit |

---

## Output Structure

```
results/
└── example.com/
    ├── subdomains.txt          All discovered subdomains
    ├── resolved.txt            DNS-resolved subdomains
    ├── live_hosts.txt          Live URLs (HTTP/HTTPS)
    ├── dns_records.json        Full DNS records per hostname
    ├── ports.json              Open port scan results
    ├── technologies.json       Technology fingerprints per host
    ├── api_endpoints.txt       Discovered API endpoints
    ├── urls.txt                Crawled and historical URLs
    ├── javascript_findings.json JS analysis results
    ├── information_leaks.json  Exposure findings
    ├── tls_findings.json       TLS/certificate analysis
    ├── security_headers.json   Header analysis
    ├── high.txt                HIGH severity findings
    ├── medium.txt              MEDIUM severity findings
    ├── low.txt                 LOW severity findings
    ├── findings.json           All findings (structured)
    ├── asset_map.json          Relationship graph
    ├── report.csv              CSV findings export
    ├── report.md               Markdown report
    ├── report.html             HTML report (dark theme)
    └── scan_summary.txt        Human-readable summary
```

---

## Risk Classification

| Severity | Criteria |
|----------|----------|
| **HIGH** | Confirmed sensitive data exposure, verified credential exposure, significant unintended information disclosure (.env files, .git directories, database credentials, hardcoded secrets) |
| **MEDIUM** | Potentially sensitive debug interfaces, exposed API documentation, risky service exposure, expiring TLS certificates, source map exposure |
| **LOW** | Informational — live hosts, technology fingerprints, missing security headers (configuration observations), ordinary open ports |

Every finding includes: Finding ID, Asset, Type, Category, Severity, Confidence, Evidence, Detection Timestamp, Remediation Guidance.

---

## Architecture

```
submap/
├── cli.py                  Typer CLI entry point
├── core/
│   ├── banner.py           ASCII banner
│   ├── config.py           ScanConfig (Pydantic)
│   ├── engine.py           Orchestration engine
│   └── models.py           All data models
├── modules/
│   ├── discovery.py        Subdomain discovery
│   ├── dns_engine.py       DNS intelligence
│   ├── live_host.py        Live host + tech fingerprint
│   ├── port_scanner.py     Naabu / Nmap / TCP connect
│   ├── api_discovery.py    API endpoint discovery
│   ├── js_analyzer.py      JavaScript analysis
│   ├── url_recon.py        URL recon (Katana, GAU)
│   ├── leak_detector.py    Information exposure
│   ├── risk_classifier.py  Risk scoring
│   └── asset_mapper.py     Relationship graph
├── reporters/
│   └── writer.py           TXT/JSON/CSV/MD/HTML output
├── db/
│   └── storage.py          SQLite scan history
└── utils/
    ├── validator.py        Domain/IP/URL validation
    └── logger.py           Structured logging
```

---

## Configuration

Default config at `~/.config/submap/config.yaml`:

```yaml
defaults:
  threads: 10
  timeout: 10
  retries: 2
  rate_limit: 30

dns:
  resolvers:
    - 8.8.8.8
    - 1.1.1.1
    - 9.9.9.9
```

---

## Security Considerations

- **Passive discovery is the default** — active scanning requires explicit opt-in flags
- **Port scanning is off by default** — requires `--ports` flag and authorized scope
- **Private IP protection** — SUBMAP blocks scanning of RFC-1918, loopback, and link-local addresses
- **Cloud metadata protection** — 169.254.169.254 and similar are blocked
- **Redirect validation** — redirects to private infrastructure are blocked
- **Secret redaction** — detected secrets are redacted in all output (only redacted prefix/suffix shown)
- **Response size limits** — large responses are capped to prevent memory exhaustion
- **Rate limiting** — built-in request rate limiting and per-host concurrency limits
- **No shell injection** — all subprocess calls use list-based argument handling

---

## Troubleshooting

**`submap: command not found`**
```bash
source ~/.bashrc   # or ~/.zshrc
# or
~/.local/bin/submap --help
```

**Import errors on Python < 3.12**
```bash
python3 --version  # must be 3.12+
sudo apt install python3.12 python3.12-venv
```

**TLS verification errors**
SUBMAP uses `verify=False` intentionally for reconnaissance — this is expected.

**Rate limit / timeout errors**
```bash
submap -d example.com --rate-limit 5 --timeout 20 --retries 3
```

**External tool not found**
SUBMAP prints a warning and continues without it. All external tools are optional.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT License — see [LICENSE](LICENSE).

---

## Author

**Kishore Baskaran** (`0xk1sh0re`)

*Built for authorized security research and attack surface management.*
