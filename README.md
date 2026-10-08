# 🔒 Container Image Security Scanner

A complete **DevSecOps** web application that scans Docker images, Dockerfiles, and project archives for CVEs, misconfigurations, exposed secrets, and risky configurations — powered by **Python, FastAPI, Trivy, and Docker**.

> **Works immediately, even without Trivy.** A built-in demo mode provides realistic sample scan data so you can explore all features right away.

---

## ✨ Features

| Feature | Details |
|---|---|
| **File Upload** | Drag-and-drop upload of `.tar` image archives, `Dockerfile`, `.zip` projects, `.yml` configs |
| **Live Scanner** | Real-time animated progress with step-by-step status polling |
| **Trivy Integration** | Full CVE vulnerability scanning via [Trivy](https://trivy.dev/) |
| **Dockerfile Analysis** | Static analysis for 9 security rules (root user, secrets, latest tags, HEALTHCHECK…) |
| **Security Score** | 0-100 score with risk level (LOW/MODERATE/HIGH/CRITICAL) |
| **Severity Charts** | SVG bar chart in the Executive Summary |
| **CVE Details** | CVSS scores, affected packages, installed vs fixed versions, NVD links |
| **Misconfigurations** | Docker/Kubernetes config security checks |
| **Remediation** | Prioritised fix recommendations for every finding |
| **Download Reports** | HTML and JSON downloadable scan reports |
| **Scan History** | In-memory history with `/api/history` JSON endpoint |
| **Demo Mode** | Realistic nginx CVE sample data when Trivy is not installed |
| **Security Gate** | CI/CD gate — configurable fail-on severity thresholds |
| **REST API** | Full FastAPI with auto-generated Swagger docs at `/api/docs` |
| **Docker / CI-CD** | Multi-stage Dockerfile, Docker Compose, GitHub Actions workflow |

---

## 🚀 Quick Start

### Option 1: Local Python (fastest)

```bash
# Install dependencies
cd container-image-security-scanner
pip install -r requirements.txt

# Start the web server
python webserver.py

# Open http://127.0.0.1:8000
```

Click **"Run Demo Scan"** to instantly see a full security dashboard — no Trivy needed.

---

### Option 2: Docker (recommended)

```bash
cd container-image-security-scanner

# Build and start (demo mode — no Trivy required)
docker-compose up web

# Open http://localhost:8000
```

---

### Option 3: Docker with real scanning

```bash
# Start with Docker socket mounted (enables real image scanning)
docker-compose up web-with-docker

# Open http://localhost:8001
# Upload a .tar archive exported with: docker save nginx:latest -o nginx.tar
```

---

## 📁 Project Structure

```
container-image-security-scanner/
├── web/                        # FastAPI web application
│   ├── app.py                  # Application factory
│   ├── routes.py               # All HTTP routes + API endpoints
│   ├── scanner_service.py      # Scan orchestration + thread management
│   ├── upload.py               # Secure file upload handler
│   ├── models.py               # Web layer data models
│   ├── demo_data.py            # Realistic sample scan data (demo mode)
│   └── templates/              # Jinja2 HTML templates
│       ├── base.html           # Shared layout, navbar, footer
│       ├── index.html          # Page 1: File Upload + scan history
│       ├── scanning.html       # Page 2: Live scanner with progress bar
│       ├── results.html        # Page 3: Dashboard with charts & CVE table
│       └── error.html          # Error pages
├── src/container_scanner/      # Core scanner library
│   ├── scanner/
│   │   ├── trivy.py            # Trivy subprocess integration
│   │   ├── parser.py           # Trivy JSON → domain models
│   │   ├── dockerfile.py       # Dockerfile static analyser (9 rules)
│   │   └── docker.py           # Docker availability check
│   ├── security/
│   │   ├── scoring.py          # Security score engine (0-100)
│   │   ├── remediation.py      # Remediation recommendation generator
│   │   └── policy.py           # Security gate / fail-on policy
│   ├── reports/
│   │   ├── html_report.py      # Standalone HTML report generator
│   │   └── json_report.py      # JSON report writer
│   ├── models.py               # Core domain models
│   └── config.py               # YAML config loader + validator
├── static/
│   ├── css/style.css           # Dark cybersecurity theme
│   └── js/app.js               # Upload, collapsibles, score ring animation
├── tests/                      # Pytest test suite
├── .github/workflows/
│   └── security-scan.yml       # GitHub Actions CI/CD pipeline
├── Dockerfile                  # Multi-stage Docker build
├── docker-compose.yml          # Compose: web (demo) + web-with-docker + CLI
├── scanner.py                  # CLI entry point
├── webserver.py                # Web server entry point (uvicorn)
├── config.yaml                 # Scanner configuration
└── requirements.txt            # Python dependencies
```

---

## 🖥️ The Three Pages

### Page 1 — File Upload (`/`)

- Drag-and-drop or file-picker upload zone
- Supports: `.tar` image archives, `Dockerfile`, `.zip` projects, `.yml` configs
- Configurable: severity levels, fail-on policy, report format
- Trivy availability banner (demo mode indicator)
- **"Run Demo Scan"** button — no file needed
- Scan history table with quick-access links

### Page 2 — Scanner (`/scan/<id>`)

- Animated 6-step progress tracker
- Animated progress bar
- Live polling of scan status every 1.2 seconds
- Auto-redirects to results when scan completes

### Page 3 — Dashboard / Results (`/scan/<id>`)

- **Security Gate banner** (PASSED / FAILED)
- **Executive Summary**: score ring (0-100), risk level, CVE counts by severity
- **SVG severity distribution bar chart**
- **Critical / High / Medium / Low vulnerability tables** with CVE links, CVSS scores, package versions
- **Misconfigurations** (Docker/Kubernetes)
- **Dockerfile security findings** with rule IDs and line numbers
- **Remediation recommendations** with What/Why/How structure
- **Download buttons**: HTML report, JSON report, vulnerabilities JSON
- **API link** to raw JSON result

---

## 📡 API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Home / upload page |
| `POST` | `/scan` | Submit a file scan |
| `POST` | `/scan/demo` | Submit a demo scan (no file) |
| `GET` | `/scan/{id}` | Scan status / results page |
| `GET` | `/scan/{id}/status` | JSON status poll (for live UI) |
| `GET` | `/scan/{id}/json` | Full scan result as JSON |
| `GET` | `/scan/{id}/report` | Download HTML report |
| `GET` | `/scan/{id}/report.json` | Download JSON report |
| `GET` | `/scan/{id}/vulnerabilities.json` | Download vulnerabilities JSON |
| `GET` | `/api/history` | All scan history (JSON) |
| `GET` | `/api/demo/data` | Demo scan result (JSON, no scan) |
| `GET` | `/health` | Health check (Trivy availability) |
| `GET` | `/api/docs` | Swagger UI |

---

## 🧪 Dockerfile Security Rules

| Rule | Severity | Description |
|---|---|---|
| `DF-001` | MEDIUM | Use of `:latest` or untagged image |
| `DF-002` | HIGH | Container running as root |
| `DF-003` | HIGH | Potential secret in `ENV` instruction |
| `DF-004` | MEDIUM | Potential secret in `ARG` instruction |
| `DF-005` | HIGH | Dangerous command in `RUN` (curl\|bash, chmod 777…) |
| `DF-006` | MEDIUM | Use of `sudo` inside container |
| `DF-007` | MEDIUM | `ADD` fetches from remote URL (no checksum) |
| `DF-008` | HIGH | Missing `USER` instruction (runs as root) |
| `DF-009` | LOW | Missing `HEALTHCHECK` instruction |

---

## 📊 Security Score Model

The score starts at **100** and deducts points per finding:

| Finding Type | Critical | High | Medium | Low |
|---|---|---|---|---|
| Vulnerability | -20 | -10 | -3 | -1 |
| Misconfiguration | -10 | -5 | -3 | -1 |
| Dockerfile Issue | -10 | -5 | -2 | -1 |

**Risk levels:** `LOW` (≥90) · `MODERATE` (≥75) · `HIGH` (≥50) · `CRITICAL` (<50)

> ⚠️ This is a project-internal scoring model. It is **not** an official industry standard (not CVSS, not NIST).

---

## ⚙️ Configuration (`config.yaml`)

```yaml
scanner:
  severity: [CRITICAL, HIGH, MEDIUM, LOW]
  timeout: 300
  trivy_path: trivy

security_gate:
  enabled: true
  fail_on: [CRITICAL, HIGH]

reports:
  formats: [json, html]

output:
  directory: reports
```

---

## 🐳 Docker

### Build only

```bash
docker build -t container-image-security-scanner .
```

### Run (demo mode, no Trivy needed)

```bash
docker run -p 8000:8000 container-image-security-scanner
```

### Run (with real scanning — Docker socket)

```bash
docker run -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/reports:/app/reports \
  container-image-security-scanner
```

### CLI mode

```bash
docker run --rm container-image-security-scanner python scanner.py --help
```

---

## 🔧 Install Trivy (for real scanning)

```bash
# macOS
brew install trivy

# Ubuntu/Debian
sudo apt-get install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# Windows (winget)
winget install AquaSecurity.Trivy

# Verify
trivy --version
```

---

## 🔄 CI/CD (GitHub Actions)

The workflow at [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml) runs:

1. **Unit Tests** — pytest with coverage
2. **Security Scan** — Trivy scan of `python:3.11-slim`, HTML + JSON reports uploaded as artifacts
3. **Docker Build** — builds the scanner image, verifies it starts, self-scans with Trivy
4. **Security Gate** — fails the workflow if CRITICAL vulnerabilities are found

Trigger manually with any Docker image name via `workflow_dispatch`.

---

## 🛡️ Security Design

- **Non-root container user** (UID 10001)
- **`shell=False` subprocess** — prevents command injection in Trivy invocation
- **ZIP slip prevention** — path traversal protection in ZIP extraction
- **File size limits** — 512 MB upload, 256 MB ZIP extraction
- **Allowed extensions** — `.tar`, `.zip`, `.yml`, `.yaml`, `Dockerfile`
- **No credentials stored** — reports written to local filesystem only

---

## 🏃 Running Tests

```bash
cd container-image-security-scanner
pip install -r requirements.txt
python -m pytest tests/ -v --tb=short --cov=src
```

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

*Made with [IBM Bob](https://www.ibm.com/products/watsonx-code-assistant)*
