# THREXIS — Threat Intelligence Platform

See the threat. Understand the risk. THREXIS is a unified cybersecurity platform that detects phishing websites, malicious URLs, suspicious certificates, and web security weaknesses through four independent detection engines and collaborative community threat intelligence.

---

## Architecture Overview

```
threxis/
├── backend/                  # FastAPI Python backend
│   ├── app/
│   │   ├── main.py           # FastAPI entry point
│   │   ├── config.py         # Pydantic settings
│   │   ├── database/         # SQLAlchemy connection + session
│   │   ├── models/           # ORM models (user, scan, threat, cert, web, community)
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── api/
│   │   │   └── routes/       # auth, scans, community, dashboard
│   │   ├── engines/          # Four detection engines + scoring
│   │   │   ├── threat_engine.py
│   │   │   ├── web_assessment.py
│   │   │   ├── certificate_engine.py
│   │   │   ├── community_engine.py
│   │   │   └── scoring_engine.py
│   │   └── services/         # url_validator, auth_service, scan_service
│   └── requirements.txt
├── frontend/                 # React + Vite + TypeScript
│   └── src/
│       ├── pages/            # Dashboard, Scanner, ScanResult, Community, etc.
│       ├── components/       # RiskBadge, StatCard, Sidebar
│       ├── services/         # API client and service functions
│       └── types/            # Shared TypeScript interfaces
├── tests/                    # Pytest test suite
├── .env.example              # Environment variable template
├── docker-compose.yml
└── README.md
```

---

## Quick Start (Development)

### Prerequisites

- Python 3.11+
- Node.js 20+
- pip

### 1. Clone and configure environment

```bash
cp .env.example .env
# Edit .env — set SECRET_KEY and optionally add API keys
```

### 2. Backend setup

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

The API is now available at `http://localhost:8000`.  
Interactive API docs: `http://localhost:8000/api/docs`

### 3. Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173`.

### 4. Run tests

```bash
# From project root
pip install pytest pytest-asyncio httpx
pytest tests/ -v
```

---

## Four Detection Engines

### Module A — Threat Intelligence Engine
Analyses URLs using:
- URL structure heuristics (IP addresses, at-symbols, brand lookalikes, suspicious TLDs, excessive subdomains)
- Shannon entropy scoring
- External integrations: Google Safe Browsing, VirusTotal, PhishTank, URLhaus
- Confirmed malicious matches apply a minimum risk floor of 70/100

**Note:** External API keys are read from environment variables. Adapters gracefully return `NOT_CONFIGURED` when keys are absent.

### Module B — Web Security Assessment Engine
Passive HTTP/HTTPS checks:
- HTTPS enforcement
- Security headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy, X-Frame-Options)
- Cookie security attributes (Secure, HttpOnly, SameSite)
- Redirect chain analysis
- Information disclosure (Server, X-Powered-By headers)
- No exploit attempts, no form submissions, no destructive operations

### Module C — TLS/SSL Certificate Intelligence Engine
- TLS handshake analysis
- Certificate expiration and validity
- Hostname / SAN matching
- Issuer trust and chain validation
- Key algorithm and key size analysis
- Signature algorithm strength (MD5/SHA-1 flagged)
- Self-signed certificate detection
- Certificate Transparency log queries (crt.sh)
- Historical certificate storage for change detection

**Important:** A valid HTTPS certificate does NOT indicate a legitimate website.

### Module D — Community Intelligence Engine
- Community URL reports with threat category classification
- Analyst/admin verification workflow
- Community voting (support / dispute) — votes alone do not classify threats
- Duplicate report detection
- Credibility scoring per reporter
- Threat campaign linkage

---

## Unified Risk Scoring

```
Risk Score =
  (Threat Intelligence × 0.35) +
  (Web Security       × 0.20) +
  (Certificate        × 0.25) +
  (Community          × 0.20)
```

| Score   | Classification |
|---------|---------------|
| 0–19    | LOW RISK      |
| 20–39   | GUARDED       |
| 40–59   | MEDIUM RISK   |
| 60–79   | HIGH RISK     |
| 80–100  | CRITICAL      |

- Weights are redistributed when engines are unavailable.
- Confirmed malicious threat matches enforce a minimum score of 70.
- Missing security headers do not make a site malicious — they contribute proportionally.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/register` | Create account |
| POST | `/api/v1/auth/login` | Login |
| GET  | `/api/v1/auth/me` | Current user |
| POST | `/api/v1/scans` | Submit URL for scanning |
| GET  | `/api/v1/scans` | List scans |
| GET  | `/api/v1/scans/{id}` | Get scan status |
| GET  | `/api/v1/scans/{id}/report` | Get full scan report |
| GET  | `/api/v1/dashboard/stats` | Dashboard statistics |
| GET  | `/api/v1/domains/{domain}/reputation` | Domain reputation |
| POST | `/api/v1/reports` | Submit community report |
| GET  | `/api/v1/reports` | List reports |
| GET  | `/api/v1/reports/{id}` | Get report detail |
| POST | `/api/v1/reports/{id}/vote` | Vote on report |
| PATCH| `/api/v1/reports/{id}/verify` | Analyst verification |
| GET  | `/api/v1/intelligence/campaigns` | Threat campaigns |
| GET  | `/api/v1/admin/users` | Admin user list |

Full Swagger docs at `/api/docs`.

---

## External API Integrations

| Provider | Environment Variable | Status when unconfigured |
|----------|---------------------|--------------------------|
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_API_KEY` | NOT_CONFIGURED |
| VirusTotal | `VIRUSTOTAL_API_KEY` | NOT_CONFIGURED |
| PhishTank | `PHISHTANK_API_KEY` | NOT_CONFIGURED |
| URLhaus | — (public) | Always active |

---

## Security Design

The scanner itself implements these protections against misuse:

- **SSRF Prevention:** Private IP ranges (RFC 1918), loopback, link-local, and cloud metadata endpoints (169.254.169.254) are blocked before any outbound connection.
- **Protocol Restriction:** Only HTTP and HTTPS are allowed.
- **Redirect Safety:** Every redirect destination is re-validated against SSRF rules.
- **Response Size Limit:** Configurable maximum response size prevents memory exhaustion.
- **Timeout Enforcement:** Strict connection and read timeouts.
- **No Credential Submission:** The scanner never submits forms, credentials, or executes page scripts.
- **API Key Isolation:** Keys are loaded from environment variables and never exposed to the frontend.

---

## Database

Uses SQLite for development. PostgreSQL-compatible via `DATABASE_URL`.

To migrate to PostgreSQL:
```bash
# In .env:
DATABASE_URL=postgresql://user:password@localhost:5432/threxis
```

---

## Docker

```bash
# Copy and configure environment
cp .env.example .env

# Start all services
docker-compose up --build
```

---

## Known Limitations and Remaining Work

1. **Background job queue:** Scans run as FastAPI background tasks. For production, replace with Celery + Redis workers.
2. **Alembic migrations:** Tables are auto-created with `create_all()`. For production, set up Alembic migrations.
3. **URLhaus:** Public endpoint, no key required. Rate limits apply.
4. **Certificate transparency:** Uses crt.sh public API. May be slow or unavailable.
5. **Frontend auth guard:** Currently uses localStorage for JWT storage. For production, consider httpOnly cookies.
6. **Admin moderation UI:** Backend API is complete; admin report moderation is accessible via API but not fully built out in the frontend admin panel.

---

## License

MIT
