# Universal Tizen GRC Compliance Assessment Platform (UTSCP)

UTSCP is a state-of-the-art Governance, Risk, and Compliance (GRC) software platform designed to operationalize the **Universal Tizen Security Compliance Framework (UTSCF)**. It provides organizations with automated assessments, vulnerability monitoring, risk tracking, and compliance dashboards for Tizen OS devices (e.g., Smart TVs, Wearable devices, Digital Signages, and Mobile environments).

---

## Technical Architecture

The platform is designed around a **three-tier architecture**:

1. **Client Layer (Frontend)**: A responsive Single Page Application (SPA) built using HTML5, CSS3, Bootstrap 5, and JavaScript. Visualizations (compliance radar charts, risk distributions) are powered by **Chart.js**.
2. **Application Layer (FastAPI Backend)**: Serves RESTful APIs, runs compliance rule matching, triggers risk score calculations, and compiles GRC report exports.
3. **Data Layer (PostgreSQL / SQLite)**: Houses relational data structures for multi-tenant organizations, sites, devices, controls library, and historical audit logs.

---

## Core Algorithms

### 1. Compliance Score Calculation
Each control \(c\) is assigned a weight based on severity:
* **CRITICAL**: \(W_c = 4\)
* **HIGH**: \(W_c = 3\)
* **MEDIUM**: \(W_c = 2\)
* **LOW**: \(W_c = 1\)

Compliance weights are resolved based on findings:
* **PASS**: \(S_c = 1.0\)
* **FAIL**: \(S_c = 0.0\)
* **PARTIALLY_COMPLIANT**: \(S_c = 0.5\)
* **NOT_APPLICABLE**: Excluded from denominator and numerator.

The Device Compliance Percentage (\(C_{\text{device}}\)) is computed as:
\[
C_{\text{device}} = \frac{\sum_{c \in \text{Applicable}} S_c \times W_c}{\sum_{c \in \text{Applicable}} W_c} \times 100
\]

### 2. Risk Scoring Algorithm
Control severity represents an inherent risk score:
* **CRITICAL**: 10
* **HIGH**: 8
* **MEDIUM**: 5
* **LOW**: 2

Control risk score contribution (\(R_c\)):
* `PASS` or `N/A`: \(R_c = 0\)
* `FAIL`: \(R_c = R_{c,\text{inherent}}\)
* `PARTIALLY_COMPLIANT`: \(R_c = R_{c,\text{inherent}} \times 0.5\)

The Device Risk Score (\(R_{\text{device}}\)) is normalized to a 100-point scale:
\[
R_{\text{device}} = \min\left(100, \frac{\sum R_c}{\sum R_{c,\text{inherent}}} \times 100\right)
\]

### 3. Security Maturity Level (1 to 5)
* **Level 1 (Initial)**: Compliance < 40%
* **Level 2 (Repeatable)**: Compliance 40% - 60%
* **Level 3 (Defined)**: Compliance 60% - 80%
* **Level 4 (Managed)**: Compliance 80% - 95% AND 100% compliance with Critical controls
* **Level 5 (Optimized)**: Compliance \(\ge\) 95% AND 100% compliance with both Critical and High controls

---

## Directory Structure

```text
tizen-grc-platform/
│
├── Dockerfile                  # Production container configuration
├── docker-compose.yml          # Orchestrates app and PostgreSQL services
│
├── backend/
│   ├── main.py                 # FastAPI application routes
│   ├── database.py             # SQLAlchemy session connection
│   ├── models.py               # ORM Database Schemas
│   ├── schemas.py              # Pydantic schema serializers
│   ├── auth.py                 # JWT token utilities & RBAC checks
│   ├── seed_data.py            # Pre-populates 130 UTSCF controls
│   ├── reports.py              # Compiles CSV/Excel/JSON reports
│   ├── requirements.txt        # Python dependency list
│   └── test_platform.py        # Automated test suite
│
└── frontend/
    ├── index.html              # Main single page interface (SPA)
    ├── login.html              # Secure JWT authentication screen
    ├── styles.css              # Custom styling definitions
    └── app.js                  # SPA routing and API controller
```

---

## REST API Specification

| Endpoint | Method | Role | Description |
| :--- | :---: | :---: | :--- |
| `/api/auth/login` | POST | Anonymous | Authenticates credentials; returns JWT token, role, and org. |
| `/api/auth/register`| POST | Admin Only | Registers a new user with custom roles and organization mappings. |
| `/api/devices` | GET | All Roles | Lists registered devices (Org scoped for non-Superadmins). |
| `/api/devices` | POST | Security Admin| Registers a new Tizen device asset. |
| `/api/controls` | GET | All Roles | Returns the UTSCF library definitions (130 Controls). |
| `/api/assessments` | GET | All Roles | Lists compliance assessments. |
| `/api/assessments` | POST | Comp Officer | Initiates a compliance assessment for a device (spawns 130 findings). |
| `/api/assessments/{id}/scan` | POST | Comp Officer | Simulates automated scan checks on configuration inputs. |
| `/api/findings/{id}` | PUT | Comp Officer | Toggles finding status (PASS/FAIL/PARTIAL) and inputs comments. |
| `/api/findings/{id}/evidence` | POST | Comp Officer | Uploads files (logs, certificates) as evidence. |
| `/api/dashboard/stats` | GET | All Roles | Compiles metrics, domain compliance percentages, and charts JSON. |
| `/api/reports/{id}/csv`| GET | Auditor | Downloads assessment report in CSV. |
| `/api/reports/{id}/excel`| GET | Auditor | Downloads Excel-compatible TSV report. |
| `/api/reports/{id}/remediation`| GET | Auditor | Retrieves JSON containing failed controls mitigation steps. |
| `/api/reports/risk-register` | GET | Auditor | Downloads organization-wide Risk Register. |

---

## Local Development Setup

### 1. Requirements
Ensure you have Python 3.10+ installed.

### 2. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
pip install email-validator sqlalchemy --upgrade
```

### 3. Run Automated Tests
```bash
python test_platform.py
```

### 4. Run Development Server
```bash
# Set PYTHONPATH to search inside the backend directory
set PYTHONPATH=./backend
uvicorn backend.main:app --reload --port 8000
```
Visit `http://localhost:8000/` in your browser. The system will automatically create database tables, seed 130 security controls, and register default users and devices.

---

## Containerized Deployment (Docker)

To launch the platform in a production configuration with a PostgreSQL cluster:

```bash
# Build and start services
docker-compose up -d --build
```
This launches:
* **Database Service** on port `5432` (PostgreSQL)
* **API Service & SPA Frontend** on port `8000` (FastAPI)

The container executes automated database health checks and handles schema migrations on startup.
