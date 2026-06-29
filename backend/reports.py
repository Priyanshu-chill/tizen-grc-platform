import csv
import io
import json
import datetime
from sqlalchemy.orm import Session
from models import Device, Assessment, Finding, SecurityControl, Organization, Site, Building, DeviceGroup

def generate_csv_report(db: Session, assessment_id: int) -> str:
    """Generates a detailed CSV compliance report for a specific device assessment."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return "Assessment not found"
        
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Metadata Headers
    writer.writerow(["UTSCF COMPLIANCE ASSESSMENT REPORT"])
    writer.writerow(["Device Name", device.name])
    writer.writerow(["Model", device.model])
    writer.writerow(["Serial Number", device.serial_number])
    writer.writerow(["Firmware Version", device.firmware_version])
    writer.writerow(["Overall Compliance %", f"{assessment.compliance_percentage:.2f}%"])
    writer.writerow(["Device Risk Score", f"{assessment.risk_score:.2f} / 100"])
    writer.writerow(["Security Maturity Level", f"Level {assessment.maturity_level}"])
    writer.writerow(["Assessment Date", assessment.created_at.strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow([])
    
    # Findings Details
    writer.writerow(["Control ID", "Security Domain", "Control Name", "Severity", "Validation Type", "Compliance Status", "Risk Score Contribution", "Assessor Comments"])
    
    for f in findings:
        ctrl = f.control
        writer.writerow([
            ctrl.control_id,
            ctrl.domain,
            ctrl.name,
            ctrl.severity,
            ctrl.validation_type,
            f.status,
            f.residual_risk,
            f.comments or ""
        ])
        
    return output.getvalue()


def generate_excel_tsv_report(db: Session, assessment_id: int) -> str:
    """Generates an Excel-compatible TSV (Tab-Separated) report with similar layout structure."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return "Assessment not found"
        
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter='\t')
    
    writer.writerow(["UTSCF COMPLIANCE ASSESSMENT REPORT (EXCEL FORMAT)"])
    writer.writerow(["Device Name", device.name])
    writer.writerow(["Model", device.model])
    writer.writerow(["Serial Number", device.serial_number])
    writer.writerow(["Firmware Version", device.firmware_version])
    writer.writerow(["Overall Compliance %", f"{assessment.compliance_percentage:.2f}%"])
    writer.writerow(["Device Risk Score", f"{assessment.risk_score:.2f}"])
    writer.writerow(["Security Maturity Level", f"Level {assessment.maturity_level}"])
    writer.writerow([])
    
    writer.writerow(["Control ID", "Security Domain", "Control Name", "Severity", "Validation Type", "Compliance Status", "Risk Score Contribution", "Assessor Comments"])
    for f in findings:
        ctrl = f.control
        writer.writerow([
            ctrl.control_id,
            ctrl.domain,
            ctrl.name,
            ctrl.severity,
            ctrl.validation_type,
            f.status,
            f.residual_risk,
            f.comments or ""
        ])
        
    return output.getvalue()


def generate_risk_register_csv(db: Session, org_id: int) -> str:
    """Generates a Risk Register CSV for all devices in an organization, listing high & critical risks."""
    devices = db.query(Device).join(Device.device_group).join(DeviceGroup.building).join(Building.site).filter(Site.organization_id == org_id).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(["UTSCF SYSTEM RISK REGISTER"])
    writer.writerow(["Report Generated", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")])
    writer.writerow([])
    
    writer.writerow(["Device Name", "Model", "Serial Number", "Overall Compliance %", "Risk Score", "Risk Rating", "Open Failed Controls Count"])
    
    for device in devices:
        # Get latest assessment
        latest_assessment = db.query(Assessment).filter(Assessment.device_id == device.id).order_by(Assessment.created_at.desc()).first()
        if latest_assessment:
            failed_count = db.query(Finding).filter(Finding.assessment_id == latest_assessment.id, Finding.status == "FAIL").count()
            
            risk_score = latest_assessment.risk_score
            if risk_score <= 20:
                rating = "LOW"
            elif risk_score <= 50:
                rating = "MEDIUM"
            elif risk_score <= 80:
                rating = "HIGH"
            else:
                rating = "CRITICAL"
                
            writer.writerow([
                device.name,
                device.model,
                device.serial_number,
                f"{latest_assessment.compliance_percentage:.2f}%",
                f"{latest_assessment.risk_score:.2f}",
                rating,
                failed_count
            ])
            
    return output.getvalue()


def generate_remediation_plan_json(db: Session, assessment_id: int) -> dict:
    """Generates a Remediation Plan structure for failed controls on a device."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return {"error": "Assessment not found"}
        
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    failed_findings = db.query(Finding).filter(Finding.assessment_id == assessment_id, Finding.status == "FAIL").all()
    
    remediation_steps = []
    
    # Tizen specific remediation templates based on domains
    remediation_guides = {
        "BHS": "Ensure Tizen Secure Boot is enabled in bootloader settings. Re-flash firmware to verify Knox TrustZone validation bits.",
        "KOH": "Apply latest kernel configurations. Update SMACK configuration files to ensure simple mandatory access controls are active.",
        "ACP": "Restore Cynara access control database policy records to default restrictive states. Remove unapproved user privilege levels.",
        "ASL": "Verify SMACK labels in tizen-manifest.xml. Reject installation of unsigned or unverified third-party binaries.",
        "CKM": "Configure cryptographic libraries to prioritize FIPS-approved cipher suites. Ensure API calls utilize secure hardware keyring.",
        "NCS": "Modify networking configurations to restrict TLS connections to TLS 1.3 only. Disable Bluetooth discoverable status when idle.",
        "DAM": "Enroll device into MDM profile. Enforce screen lockout and PIN complexity requirements.",
        "LAM": "Verify security audit daemon (auditd) service state. Ensure system syslog forwarding is active.",
        "PVM": "Trigger Over-the-Air (OTA) firmware upgrade to patch vulnerability targets.",
        "PIO": "Disable Smart Development Bridge (SDB/USB Debugging) access in settings. Disable unused USB peripheral mounts."
    }
    
    for f in failed_findings:
        ctrl = f.control
        domain_prefix = ctrl.control_id.split("-")[1]
        guide = remediation_guides.get(domain_prefix, "Analyze control parameters and verify policy compliance requirements.")
        
        remediation_steps.append({
            "control_id": ctrl.control_id,
            "control_name": ctrl.name,
            "domain": ctrl.domain,
            "severity": ctrl.severity,
            "inherent_risk": f.inherent_risk,
            "description": ctrl.description,
            "recommended_action": guide,
            "timeline": "Immediate (24 hours)" if ctrl.severity == "CRITICAL" else "7 Days" if ctrl.severity == "HIGH" else "30 Days"
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
