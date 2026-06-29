# UTSGRCP v3.0: M.Tech Research & Development Thesis Documentation

This documentation serves as the master technical reference and thesis guide for the **Enterprise Universal Tizen Security Governance, Risk & Compliance Platform (UTSGRCP) Version 3.0**.

---

## Section 1: R&D Context of Tizen OS

### 1.1 Architectural History & Core Structure
Tizen OS is a Linux-kernel-based open-source operating system. Its ancestry traces back to the merger of several mobile Linux projects:
* **MeeGo** (a joint venture of Intel's Moblin and Nokia's Maemo)
* **LiMo** (Linux Mobile foundation)
* **Tizen Project** (launched by Samsung and Intel in 2011, managed by the Linux Foundation)

```text
       ┌────────────────────────────────────────────────────────┐
       │             Tizen Web & Native Applications            │
       ├────────────────────────────────────────────────────────┤
       │             Tizen Application Framework API            │
       ├───────────────────┬───────────────────┬────────────────┤
       │  Base Middleware  │  Security System  │  Connectivity  │
       │  (D-Bus, Systemd) │  (SMACK & Cynara) │ (WiFi, BlueZ)  │
       ├───────────────────┴───────────────────┴────────────────┤
       │             Linux Kernel (with SMACK LSM)              │
       └────────────────────────────────────────────────────────┘
```

### 1.2 Tizen Security Subsystems
Unlike standard Linux systems which rely solely on discretionary access controls (DAC - user/group permissions), Tizen enforces two major mandatory security components:
1. **SMACK (Simplified Mandatory Access Control Kernel)**:
   * Implemented as a Linux Security Module (LSM).
   * Dictates file and process access based on cryptographic labels (e.g. process with label `UserApp` cannot access file with label `SystemKey` unless an explicit SMACK rule permits it).
2. **Cynara**:
   * Tizen's decentralized user-space security policy database.
   * Resolves application permission queries (e.g. "Does application X have permission to access the camera API?").
   * Access decisions are stored in a high-speed cached database `/var/lib/cynara/`.

---

## Section 2: Samsung Tizen Device Ecosystem

Samsung utilizes Tizen OS across a massive fleet of consumer and commercial B2B devices:

* **Samsung Smart Kiosks (KM24A Series)**: Used in retail, quick-service restaurants, and hospitality for point-of-sale checkouts.
* **Samsung Smart Signage (QM/QB Series)**: Large-format displays used in airports, shopping malls, and corporate offices.
* **Smart TVs & Hospitality TVs**: Interactive displays deployed in hotel rooms and consumer living rooms.
* **Smart Home Appliances (Family Hub)**: Refrigerator panels, smart washing machines, and local IoT hubs.
* **Wearables**: Samsung Gear and early Galaxy Watch generations ran Tizen Wearable profiles.

---

## Section 3: Project Motivation (Why we built this)

1. **Security Gaps in Commercial IoT**: Displays and kiosks are often placed in physically unsecured public areas. If an attacker accesses the physical ports or exploits unpatched network services, they can gain root access to the corporate network.
2. **The "SDB" Vulnerability Vector**: Smart Development Bridge (SDB) is Tizen's debugger port (running on port `26101`). If left active after installation, anyone on the network can execute commands, bypass app signature checks, and upload malware.
3. **No Existing Tooling**: Enterprise security tools (like Nessus, Qualys, or Defender) do not parse Tizen-specific controls (e.g., Cynara db rules, SMACK settings, or Knox warranty bits). UTSGRCP bridges this gap by providing dedicated GRC analytics for Tizen OS.

---

## Section 4: Universal Tizen Security Compliance Framework (UTSCF)

The platform evaluates devices against exactly **130 controls** across **10 security domains**:

| Domain | Focus Area | Example Check |
| :--- | :--- | :--- |
| **BHS** | Boot & Hardware Security | Secure Boot state & Knox warranty bit verification. |
| **KOH** | Kernel & OS Hardening | ASLR kernel parameters & SMACK LSM mounting. |
| **ACP** | Access Control & Privilege | Cynara policy DB configurations & root shell limitations. |
| **ASL** | App Sandboxing & Lifecycle | Package developer signatures & SMACK directory bounds. |
| **CKM** | Crypto & Key Management | FIPS-compliant cipher usage & secure hardware keystores. |
| **NCS** | Network & Communication | Enforcing TLS 1.3 & disabling Bluetooth discoverable state. |
| **DAM** | Device Administration | MDM enrollment status & passkey complexity checks. |
| **LAM** | Logging, Audit & Monitoring | auditd service state & SIEM syslog forwarding. |
| **PVM** | Patch & Vulnerability | Firmware build checks & OTA verification. |
| **PIO** | Peripheral & I/O Security | USB port blockouts & SDB debugging lockdown. |

---

## Section 5: Technical Reference Architecture

The platform's processing pipeline and persistence layers are structured to ensure security and scalability:

```text
              Presentation Layer (Glassmorphic Web SPA)
                          │
                          ▼
                    REST API Layer (FastAPI Controllers)
                          │
                          ▼
            Authentication Layer (JWT & Role-Based Access Control)
                          │
                          ▼
            Configuration Collection Layer (Pluggable Abstraction)
                          │
                          ▼
             Policy Engine (Policy-as-Code & JSON Schemas)
                          │
                          ▼
                Compliance Engine (Rule Evaluator)
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
    Risk Engine      Drift Engine    Evidence Engine
         └────────────────┼────────────────┘
                          │
                          ▼
               Security Posture Engine (Weighted Math)
                          │
                          ▼
         Recommendation & Prioritization (Priority Index)
                          │
                          ▼
                 Reporting Engine (PDF/HTML/CSV)
                          │
                          ▼
                 Persistence Layer (SQLite/PostgreSQL & Evidence Files)
                          │
                          ▼
                 Executive Dashboard (Console)
```

---

## Section 6: Operational Workflow Sequences

### 6.1 Telemetry Ingestion Flow
1. **Collector Telemetry Capture**: Telemetry is gathered from the physical kiosk (via SDB, Config Files, or MDM APIs).
2. **FastAPI Submission**: The collector POSTs payload checks to the API `/api/assessments/{id}/scan`.
3. **Database Write**: The findings are committed to the SQL database.
4. **Scoring Engine**: Evaluates Posture, Attack Surface, and Risk scores, writing updates back to the database.
5. **Drift Detection**: Emits an alert if any finding degrades (e.g., changes from `PASS` to `FAIL`).

### 6.2 Risk Exception (Waiver) Lifecycle
1. **Analyst Request**: Analyst selects a failed control in the UI and requests a Risk Exception.
2. **Parameter Definition**: Specifies the business justification and expiry duration (in days).
3. **Engine Update**: Backend flags the finding's `risk_accepted` flag.
4. **Recalculation**: The **Residual Risk** drops to `0.0`, reflecting temporary risk acceptance.
5. **Expiry**: When the time limit expires, the waiver is cancelled, and the risk metric resets.

---

## Section 7: Mathematical Engines

### 7.1 Inherent Risk Formula
$$Risk_{\text{inherent}} = Impact_{\text{severity}} \times Weight_{\text{control}} \times Criticality_{\text{device}}$$

### 7.2 Residual Risk Formula
$$Risk_{\text{residual}} = Risk_{\text{inherent}} \times (1.0 - Effectiveness_{\text{control}}) \times Waiver_{\text{aging}}$$
*Where $Waiver_{\text{aging}} = 0.0$ if a risk exception is active, otherwise $1.0$.*

### 7.3 Security Posture Score (0-100)
$$Posture = 0.35 \cdot Compliance + 0.25 \cdot (100 - Risk_{\text{residual}}) + 0.15 \cdot Patch + 0.15 \cdot Evidence + 0.10 \cdot (100 - AttackSurface)$$

### 7.4 Attack Surface Index
$$AttackSurface = \sum_{c \in Categories} Weight_{c} \cdot Score_{c}$$
*Categories are: Network (25%), Wireless (15%), Physical (20%), Application (20%), and Configuration (20%).*

### 7.5 Recommendation Prioritization Index
$$PriorityScore = Risk_{\text{residual}} \times Exploitability \times \frac{AttackSurface}{10.0}$$
*Critical prioritization SLA timelines: Immediate (Priority >= 80), Short-Term (40-79), and Long-Term (< 40).*
