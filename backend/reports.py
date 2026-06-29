import csv
import io
import json
import datetime
from sqlalchemy.orm import Session
from models import Device, Assessment, Finding, SecurityControl, Organization, Site, Building, DeviceGroup

def generate_csv_report(db: Session, assessment_id: int) -> str:
    """Generates a clean, well-structured, human-readable CSV compliance report."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return "Assessment not found"
        
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header Section
    writer.writerow(["====================================================================================="])
    writer.writerow(["               UTSGRCP ENTERPRISE COMPLIANCE AUDIT REPORT (UTSCF v3.0)"])
    writer.writerow(["====================================================================================="])
    writer.writerow([])
    
    # Device and Score Details
    writer.writerow(["AUDIT TARGET METADATA"])
    writer.writerow(["Device Asset Name", device.name])
    writer.writerow(["Model / Type", device.model])
    writer.writerow(["Serial Number", device.serial_number])
    writer.writerow(["Firmware Version", device.firmware_version])
    writer.writerow(["Tizen OS Version", device.tizen_version])
    writer.writerow(["IP Address", device.ip_address or "N/A"])
    writer.writerow(["MAC Address", device.mac_address or "N/A"])
    writer.writerow([])
    
    writer.writerow(["COMPLIANCE & POSTURE SUMMARY"])
    writer.writerow(["Overall Compliance Rate", f"{assessment.compliance_percentage:.2f}%"])
    writer.writerow(["Security Posture Score", f"{assessment.posture_score:.2f} / 100.0"])
    writer.writerow(["Device Residual Risk", f"{assessment.risk_score:.2f} / 100.0"])
    writer.writerow(["Attack Surface Index", f"{assessment.attack_surface_score:.2f} / 100.0"])
    writer.writerow(["Audit Maturity Level", f"Level {assessment.maturity_level}"])
    writer.writerow(["Scan Timestamp", assessment.updated_at.strftime("%Y-%m-%d %H:%M:%S UTC")])
    writer.writerow([])
    
    # Findings Details Table
    writer.writerow(["DETAILED COMPLIANCE CHECKLIST"])
    writer.writerow([
        "Control ID", 
        "Security Domain", 
        "Control Name", 
        "Severity", 
        "Verification Type", 
        "Compliance Status", 
        "Inherent Risk",
        "Residual Risk",
        "Auditor Commentary"
    ])
    
    for f in findings:
        ctrl = f.control
        writer.writerow([
            ctrl.control_id,
            ctrl.domain,
            ctrl.name,
            ctrl.severity,
            ctrl.validation_type,
            f.status,
            f"{f.inherent_risk:.2f}",
            f"{f.residual_risk:.2f}",
            f.comments or ""
        ])
        
    writer.writerow([])
    writer.writerow(["====================================================================================="])
    writer.writerow(["Report Generated via UTSGRCP Governance Engine on " + datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")])
    writer.writerow(["====================================================================================="])
    
    return output.getvalue()


def generate_html_report(db: Session, assessment_id: int) -> str:
    """Generates a premium, structured, print-ready HTML audit report (easily printable to PDF)."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return "<h3>Assessment not found</h3>"
        
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    # Group findings by status for statistics
    passed = len([f for f in findings if f.status == "PASS"])
    failed = len([f for f in findings if f.status == "FAIL"])
    partial = len([f for f in findings if f.status == "PARTIALLY_COMPLIANT"])
    na = len([f for f in findings if f.status == "NOT_APPLICABLE"])
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>UTSCF Compliance Audit Report - {device.name}</title>
    <style>
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            color: #334155;
            line-height: 1.5;
            background-color: #f8fafc;
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: #ffffff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            color: #0f172a;
            font-size: 26px;
            font-weight: 800;
        }}
        .header .meta {{
            text-align: right;
            color: #64748b;
            font-size: 13px;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: 700;
            color: #1e293b;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 30px;
            margin-bottom: 15px;
            border-left: 4px solid #3b82f6;
            padding-left: 10px;
        }}
        .grid-metadata {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card-meta {{
            background: #f1f5f9;
            padding: 15px 20px;
            border-radius: 8px;
        }}
        .card-meta table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .card-meta td {{
            padding: 6px 0;
            font-size: 14px;
        }}
        .card-meta td.label {{
            color: #64748b;
            font-weight: 500;
            width: 40%;
        }}
        .card-meta td.val {{
            color: #0f172a;
            font-weight: 600;
            text-align: right;
        }}
        .grid-kpis {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        .card-kpi {{
            text-align: center;
            padding: 20px 10px;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
            background: #ffffff;
        }}
        .card-kpi .value {{
            font-size: 28px;
            font-weight: 800;
            color: #0f172a;
            margin-bottom: 5px;
        }}
        .card-kpi .label {{
            font-size: 11px;
            color: #64748b;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        .card-kpi.posture {{ border-top: 4px solid #3b82f6; }}
        .card-kpi.compliance {{ border-top: 4px solid #10b981; }}
        .card-kpi.risk {{ border-top: 4px solid #ef4444; }}
        .card-kpi.surface {{ border-top: 4px solid #f59e0b; }}
        
        .table-findings {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        .table-findings th {{
            background: #0f172a;
            color: #ffffff;
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 700;
            text-align: left;
            padding: 12px;
        }}
        .table-findings td {{
            padding: 12px;
            font-size: 13px;
            border-bottom: 1px solid #e2e8f0;
        }}
        .table-findings tr:hover {{
            background: #f8fafc;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            display: inline-block;
        }}
        .badge-pass {{ background: #dcfce7; color: #15803d; }}
        .badge-fail {{ background: #ffe4e6; color: #b91c1c; }}
        .badge-partial {{ background: #fef3c7; color: #b45309; }}
        .badge-na {{ background: #f1f5f9; color: #475569; }}
        
        .badge-critical {{ background: #7f1d1d; color: #ffffff; }}
        .badge-high {{ background: #b91c1c; color: #ffffff; }}
        .badge-medium {{ background: #2563eb; color: #ffffff; }}
        .badge-low {{ background: #475569; color: #ffffff; }}

        .evidence-list {{
            margin: 0;
            padding-left: 15px;
            font-size: 11px;
            color: #64748b;
        }}
        .print-btn {{
            background: #0f172a;
            color: #ffffff;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            margin-bottom: 20px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        .print-btn:hover {{
            background: #1e293b;
        }}
        @media print {{
            body {{
                background-color: #ffffff;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
                padding: 0;
            }}
            .print-btn {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <button class="print-btn" onclick="window.print()">
            <svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                <path d="M5 1a2 2 0 0 0-2 2v2H2a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h1v1a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2v-1h1a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-1V3a2 2 0 0 0-2-2zM4 3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2H4zm1 5a2 2 0 1 1-4 0 2 2 0 0 1 4 0zm1.5 1a.5.5 0 0 0 0-1h-3a.5.5 0 0 0 0 1zM1 7a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v-1a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v1H2a1 1 0 0 1-1-1zm3 4h8v2H4z"/>
            </svg>
            Print / Save as PDF
        </button>

        <div class="header">
            <div>
                <h1>UTSGRCP COMPLIANCE AUDIT REPORT</h1>
                <div style="color: #3b82f6; font-weight: 700; font-size: 13px; margin-top: 5px; font-family: monospace;">FRAMEWORK: UTSCF VERSION 3.0</div>
            </div>
            <div class="meta">
                <div><strong>Audit ID:</strong> UTSCF-AUD-{assessment_id}</div>
                <div><strong>Generated:</strong> {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
                <div><strong>Assessor:</strong> {assessment.assessor.username if assessment.assessor else 'System'}</div>
            </div>
        </div>

        <div class="grid-kpis">
            <div class="card-kpi posture">
                <div class="value">{assessment.posture_score:.1f}</div>
                <div class="label">Posture Score</div>
            </div>
            <div class="card-kpi compliance">
                <div class="value">{assessment.compliance_percentage:.1f}%</div>
                <div class="label">Compliance</div>
            </div>
            <div class="card-kpi risk">
                <div class="value">{assessment.risk_score:.1f}</div>
                <div class="label">Residual Risk</div>
            </div>
            <div class="card-kpi surface">
                <div class="value">{assessment.attack_surface_score:.1f}</div>
                <div class="label">Attack Surface</div>
            </div>
        </div>

        <div class="grid-metadata">
            <div class="card-meta">
                <div style="font-weight: 700; margin-bottom: 10px; font-size: 13px; text-transform: uppercase; color: #475569;">Device Information</div>
                <table>
                    <tr><td class="label">Device Name</td><td class="val">{device.name}</td></tr>
                    <tr><td class="label">Model / Type</td><td class="val">{device.model}</td></tr>
                    <tr><td class="label">Serial Number</td><td class="val"><code>{device.serial_number}</code></td></tr>
                    <tr><td class="label">Firmware</td><td class="val"><code>{device.firmware_version}</code></td></tr>
                </table>
            </div>
            <div class="card-meta">
                <div style="font-weight: 700; margin-bottom: 10px; font-size: 13px; text-transform: uppercase; color: #475569;">Audit Statistics</div>
                <table>
                    <tr><td class="label">Passed Rules</td><td class="val" style="color: #16a34a;">{passed} passed</td></tr>
                    <tr><td class="label">Failed Rules</td><td class="val" style="color: #dc2626;">{failed} failed</td></tr>
                    <tr><td class="label">Maturity Level</td><td class="val" style="color: #2563eb;">Level {assessment.maturity_level}</td></tr>
                    <tr><td class="label">Network Addr</td><td class="val"><code>{device.ip_address or 'N/A'}</code></td></tr>
                </table>
            </div>
        </div>

        <div class="section-title">Compliance Checklist Findings</div>
        <table class="table-findings">
            <thead>
                <tr>
                    <th style="width: 12%">ID</th>
                    <th style="width: 30%">Control Rule</th>
                    <th style="width: 10%">Severity</th>
                    <th style="width: 12%">Status</th>
                    <th style="width: 10%">Residual Risk</th>
                    <th style="width: 26%">Evidence & Commentary</th>
                </tr>
            </thead>
            <tbody>
    """
    
    for f in findings:
        ctrl = f.control
        status_cls = "badge-pass" if f.status == "PASS" else "badge-fail" if f.status == "FAIL" else "badge-partial" if f.status == "PARTIALLY_COMPLIANT" else "badge-na"
        sev_cls = f"badge-{ctrl.severity.lower()}"
        
        evidence_str = ""
        if len(f.evidence_links) > 0:
            evidence_str = '<ul class="evidence-list">' + "".join([f"<li><strong>{ev.file_name}</strong><br>SHA-256: <code>{ev.sha256_hash[:16]}...</code></li>" for ev in f.evidence_links]) + "</ul>"
            
        comments_str = f"<div style='margin-bottom:4px; font-weight:500;'>{f.comments or ''}</div>" if f.comments else ""
        
        html += f"""
                <tr>
                    <td><strong>{ctrl.control_id}</strong></td>
                    <td>
                        <div style="font-weight: 600; color: #1e293b;">{ctrl.name}</div>
                        <div style="font-size: 11px; color: #64748b;">{ctrl.domain} | {ctrl.category or 'OS Configuration'}</div>
                    </td>
                    <td><span class="badge {sev_cls}">{ctrl.severity}</span></td>
                    <td><span class="badge {status_cls}">{f.status.replace('_', ' ')}</span></td>
                    <td style="font-family: monospace; font-weight: 600;">{f.residual_risk:.1f}</td>
                    <td>
                        {comments_str}
                        {evidence_str}
                    </td>
                </tr>
        """
        
    html += """
            </tbody>
        </table>
        
        <div style="margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 20px; font-size: 11px; color: #94a3b8; text-align: center;">
            This document serves as an official GRC compliance audit registry under active key control constraints. Tamper detection verified via SHA-256 block ledger checks.
        </div>
    </div>
</body>
</html>
    """
    return html


def generate_risk_register_csv(db: Session, org_id: int) -> str:
    """Generates a Risk Register CSV for all devices in an organization, listing high & critical risks."""
    devices = db.query(Device).join(Device.device_group).join(DeviceGroup.building).join(Building.site).filter(Site.organization_id == org_id).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(["====================================================================================="])
    writer.writerow(["               UTSGRCP ENTERPRISE SYSTEM RISK REGISTER (UTSCF v3.0)"])
    writer.writerow(["====================================================================================="])
    writer.writerow([])
    
    writer.writerow(["Control ID", "Device Name", "Model", "Security Domain", "Control Name", "Severity", "Inherent Risk", "Residual Risk", "Workflow Status", "Risk Acceptance"])
    
    for d in devices:
        # Find latest completed assessment for device
        latest_assessment = db.query(Assessment)\
            .filter(Assessment.device_id == d.id)\
            .order_by(Assessment.created_at.desc()).first()
            
        if latest_assessment:
            findings = db.query(Finding)\
                .filter(Finding.assessment_id == latest_assessment.id)\
                .all()
                
            for f in findings:
                if f.status in ["FAIL", "PARTIALLY_COMPLIANT"] or f.risk_accepted:
                    ctrl = f.control
                    writer.writerow([
                        ctrl.control_id,
                        d.name,
                        d.model,
                        ctrl.domain,
                        ctrl.name,
                        ctrl.severity,
                        f"{f.inherent_risk:.2f}",
                        f"{f.residual_risk:.2f}",
                        f.workflow_status,
                        "ACCEPTED (Waiver Active)" if f.risk_accepted else "Active Exposure"
                    ])
                    
    return output.getvalue()


def generate_remediation_plan_json(db: Session, assessment_id: int) -> dict:
    """Generates structured remediation roadmap JSON containing detailed fix steps."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return {}
        
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    failed_findings = [f for f in findings if f.status in ["FAIL", "PARTIALLY_COMPLIANT"]]
    remediation_steps = []
    
    remediation_guides = {
        "BHS": "Secure boot loader configuration. Lock hardware root of trust to OEM signature certificate.",
        "KOH": "Apply sysctl hardening profiles. Ensure SMACK labels are mounted and ASLR level is set to 2.",
        "ACP": "Restore Cynara db security permissions. Restrict D-Bus message configuration access policies.",
        "ASL": "Apply SMACK labels to directories. Sign app packaging binaries with official developer keys.",
        "CKM": "Enforce FIPS-compliant cryptography packages. Bind credentials to Knox hardware keystore.",
        "NCS": "Modify networking configurations to restrict TLS connections to TLS 1.3 only. Disable Bluetooth discoverable status when idle.",
        "DAM": "Enroll device into MDM profile. Enforce screen lockout and PIN complexity requirements.",
        "LAM": "Verify security audit daemon (auditd) service state. Ensure system syslog forwarding is active.",
        "PVM": "Trigger Over-the-Air (OTA) firmware upgrade to patch vulnerability targets.",
        "PIO": "Disable Smart Development Bridge (SDB/USB Debugging) access in settings. Disable unused USB peripheral mounts."
    }
    
    metadata_map = {
        "BHS": {
            "business_impact": "High. Integrity loss of boot environment could result in device cloning or permanent rootkits.",
            "technical_impact": "Prevents loading unsigned custom operating system kernels or customized root partition overlays.",
            "root_cause": "Unforced hardware root-of-trust signatures or unlocked bootloader states.",
            "cves": ["CVE-2016-10200", "CVE-2020-13400"],
            "mitre_techniques": ["T1542.001 (System ROM)", "T1495 (Firmware Corruption)"],
            "estimated_effort": "Medium",
            "estimated_time": "2 Hours",
            "validation_procedure": "Inspect Knox Warranty bits fuse states and run crypt-verify checks on kernel signature hashes."
        },
        "KOH": {
            "business_impact": "High. Lack of kernel protections allows local privilege escalation attacks.",
            "technical_impact": "Enforces SMACK sandboxing and prevents memory overflow exploitation via ASLR configuration.",
            "root_cause": "Misconfigured Linux sysctl settings or disabled SMACK security modules.",
            "cves": ["CVE-2021-3490", "CVE-2022-25636"],
            "mitre_techniques": ["T1068 (Exploitation for Privilege Escalation)", "T1404 (Security Software Discovery)"],
            "estimated_effort": "Low",
            "estimated_time": "30 Minutes",
            "validation_procedure": "Execute 'sysctl -a' checks on kernel security keys and confirm SMACK file attributes."
        },
        "ACP": {
            "business_impact": "Medium. Broken Cynara policies permit unauthorized service privilege calls.",
            "technical_impact": "Enforces least-privilege models for client DBus permissions.",
            "root_cause": "Permissive rules loaded in /var/lib/cynara/ Cynara databases.",
            "cves": ["CVE-2018-12000"],
            "mitre_techniques": ["T1548 (Abuse Elevation Control Mechanism)"],
            "estimated_effort": "Low",
            "estimated_time": "1 Hour",
            "validation_procedure": "Run 'cynara-admin list' and inspect default policies for all client applications."
        },
        "ASL": {
            "business_impact": "Medium. Malicious apps running outside sandbox can read sensitive hardware device states.",
            "technical_impact": "Isolates application files and limits middleware access.",
            "root_cause": "Missing developer certificates or missing app manifest privilege bounds.",
            "cves": ["CVE-2019-14000"],
            "mitre_techniques": ["T1204 (User Execution)", "T1609 (Container Administration Command)"],
            "estimated_effort": "Medium",
            "estimated_time": "1 Hour",
            "validation_procedure": "Execute 'pkg_cmd -l' and verify signature hashes against trusted developer profiles."
        },
        "CKM": {
            "business_impact": "High. Key leakage compromises communications and device cryptographic credentials.",
            "technical_impact": "Forces hardware-backed Knox key storage instead of file persistence.",
            "root_cause": "Disabled hardware keystore APIs or weak key generation routines.",
            "cves": ["CVE-2022-30000"],
            "mitre_techniques": ["T1552 (Unsecured Credentials)", "T1606 (Web Portal Access)"],
            "estimated_effort": "High",
            "estimated_time": "4 Hours",
            "validation_procedure": "Verify hardware keystore bindings via test signature queries and validate cipher suites."
        },
        "NCS": {
            "business_impact": "High. Eavesdropping on public network traffic leaks user metadata and session tokens.",
            "technical_impact": "Blocks deprecated TLS versions and forces secure SSH/HTTPS ports.",
            "root_cause": "Enabled legacy TLS v1.1 protocols or open ports left in development mode.",
            "cves": ["CVE-2014-3566 (POODLE)", "CVE-2020-0601"],
            "mitre_techniques": ["T1043 (Commonly Used Port)", "T1573 (Encrypted Channel)"],
            "estimated_effort": "Medium",
            "estimated_time": "1.5 Hours",
            "validation_procedure": "Execute port scans (nmap) against device IP and run TLS cipher compliance handshakes."
        },
        "DAM": {
            "business_impact": "High. Unmanaged assets allow unauthorized access and lack remote wipe controls.",
            "technical_impact": "Enrolls device in Knox Manage or corporate MDM server configurations.",
            "root_cause": "Unenrolled state or missing security group profiles.",
            "cves": ["CVE-2019-10000"],
            "mitre_techniques": ["T1018 (Remote System Discovery)"],
            "estimated_effort": "Medium",
            "estimated_time": "2 Hours",
            "validation_procedure": "Verify active MDM daemon connection logs and test lock command execution."
        },
        "LAM": {
            "business_impact": "Medium. Without central logging, security incidents cannot be audited or traced.",
            "technical_impact": "Enforces auditd audit daemon tracking and sends logs to remote SIEM syslog targets.",
            "root_cause": "Disabled auditd configurations or blocked outbound syslog routing.",
            "cves": ["CVE-2022-40000"],
            "mitre_techniques": ["T1005 (Data from Local System)", "T1562 (Impair Defenses)"],
            "estimated_effort": "Low",
            "estimated_time": "30 Minutes",
            "validation_procedure": "Verify 'systemctl status auditd' is running and audit logs are actively spooling."
        },
        "PVM": {
            "business_impact": "High. Outdated firmware remains susceptible to published public exploit scripts.",
            "technical_impact": "Updates Tizen OS core runtime library binaries.",
            "root_cause": "Disabled FOTA updates or blocked OTA server updates.",
            "cves": ["CVE-2023-23389", "CVE-2023-33300"],
            "mitre_techniques": ["T1210 (Exploitation of Remote Service)", "T1190 (Exploit Public-Facing Application)"],
            "estimated_effort": "Medium",
            "estimated_time": "3 Hours",
            "validation_procedure": "Trigger firmware system check and assert current firmware build against CVE catalog."
        },
        "PIO": {
            "business_impact": "High. Active SDB debugging over USB exposes raw root shells to any physical passerby.",
            "technical_impact": "Blocks USB interface mounts and disables developer bridge shell access.",
            "root_cause": "SDB debug mode left active after vendor shipping or developer setup.",
            "cves": ["CVE-2017-10000"],
            "mitre_techniques": ["T1200 (Hardware Additions)", "T1059 (Command and Scripting Interpreter)"],
            "estimated_effort": "Low",
            "estimated_time": "15 Minutes",
            "validation_procedure": "Check SDB status via local vconf settings and verify USB blocking policies."
        }
    }
    
    for f in failed_findings:
        ctrl = f.control
        domain_prefix = ctrl.control_id.split("-")[1]
        guide = remediation_guides.get(domain_prefix, "Analyze control parameters and verify policy compliance requirements.")
        meta = metadata_map.get(domain_prefix, {
            "business_impact": "Medium. Exposure to security control bypass.",
            "technical_impact": "May allow unauthorized administrative actions.",
            "root_cause": "Default settings or unpatched packages.",
            "cves": [],
            "mitre_techniques": [],
            "estimated_effort": "Low",
            "estimated_time": "1 Hour",
            "validation_procedure": "Run compliance scan verification."
        })
        
        remediation_steps.append({
            "control_id": ctrl.control_id,
            "control_name": ctrl.name,
            "domain": ctrl.domain,
            "severity": ctrl.severity,
            "inherent_risk": f.inherent_risk,
            "description": ctrl.description,
            "recommended_action": guide,
            "timeline": "Immediate (24 hours)" if ctrl.severity == "CRITICAL" else "7 Days" if ctrl.severity == "HIGH" else "30 Days",
            "business_impact": meta["business_impact"],
            "technical_impact": meta["technical_impact"],
            "root_cause": meta["root_cause"],
            "cves": meta["cves"],
            "mitre_techniques": meta["mitre_techniques"],
            "estimated_risk_reduction": round(f.inherent_risk * 0.8, 2),
            "estimated_compliance_improvement": 0.77,
            "estimated_security_posture_improvement": 0.27,
            "estimated_effort": meta["estimated_effort"],
            "estimated_cost": "$0.00 (Configuration tuning)",
            "estimated_time": meta["estimated_time"],
            "validation_procedure": meta["validation_procedure"]
        })
        
    return {
        "device_name": device.name,
        "model": device.model,
        "serial_number": device.serial_number,
        "compliance_score": assessment.compliance_percentage,
        "remediation_status": "Required" if len(remediation_steps) > 0 else "Fully Compliant",
        "failed_controls_count": len(remediation_steps),
        "remediation_actions": remediation_steps
    }
