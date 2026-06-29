import datetime
import json
from sqlalchemy.orm import Session
from models import Device, Assessment, Finding, SecurityControl, Evidence, User, ConfigDrift, Notification

# --- SECURITY POSTURE ENGINE ---
def calculate_security_posture(db: Session, assessment_id: int) -> dict:
    """
    Computes Security Posture Score (0-100) based on:
    - Compliance Percentage (35%)
    - Residual Risk (25%)
    - Patch Compliance (15%)
    - Evidence Completeness (15%)
    - Attack Surface (10%)
    """
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return {"posture_score": 0.0, "compliance": 0.0, "residual_risk": 100.0}
        
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    # 1. Compliance
    compliance = assessment.compliance_percentage
    
    # 2. Residual Risk (recalculated by advanced risk engine)
    recalculate_assessment_risks(db, assessment_id)
    residual_risk = assessment.risk_score
    
    # 3. Patch Compliance (UTSCF-PVM controls)
    patch_findings = [f for f in findings if f.control.control_id.startswith("UTSCF-PVM")]
    patch_passed = [f for f in patch_findings if f.status == "PASS"]
    patch_compliance = 100.0
    if len(patch_findings) > 0:
        patch_compliance = (len(patch_passed) / len(patch_findings)) * 100
        
    # 4. Evidence Completeness
    failed_or_partial = [f for f in findings if f.status in ["FAIL", "PARTIALLY_COMPLIANT"]]
    evidence_count = 0
    for f in failed_or_partial:
        if len(f.evidence_links) > 0:
            evidence_count += 1
    evidence_completeness = 100.0
    if len(failed_or_partial) > 0:
        evidence_completeness = (evidence_count / len(failed_or_partial)) * 100
        
    # 5. Attack Surface
    attack_surface = calculate_attack_surface(db, assessment_id)
    
    # Combined Score
    posture_score = (
        0.35 * compliance +
        0.25 * (100.0 - residual_risk) +
        0.15 * patch_compliance +
        0.15 * evidence_completeness +
        0.10 * (100.0 - attack_surface)
    )
    
    # Save back to assessment
    assessment.posture_score = posture_score
    assessment.attack_surface_score = attack_surface
    db.commit()
    
    return {
        "posture_score": round(posture_score, 2),
        "compliance": round(compliance, 2),
        "residual_risk": round(residual_risk, 2),
        "patch_compliance": round(patch_compliance, 2),
        "evidence_completeness": round(evidence_completeness, 2),
        "attack_surface": round(attack_surface, 2)
    }


# --- ADVANCED RISK ENGINE ---
def recalculate_assessment_risks(db: Session, assessment_id: int):
    """
    Recalculates Inherent vs. Residual Risks, Control Effectiveness,
    taking into account active Risk Exceptions and Exceptions Expirations.
    """
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return
        
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    criticality_map = {"HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}
    severity_map = {"CRITICAL": 5.0, "HIGH": 4.0, "MEDIUM": 3.0, "LOW": 1.0}
    
    bc = criticality_map.get(device.business_criticality, 2.0)
    
    total_inherent = 0.0
    total_residual = 0.0
    
    now = datetime.datetime.utcnow()
    
    for f in findings:
        ctrl = f.control
        impact = severity_map.get(ctrl.severity, 2.0)
        weight = ctrl.control_weight
        
        # Calculate Inherent Risk
        inherent = impact * weight * bc
        f.inherent_risk = inherent
        f.impact = impact
        
        # Calculate Control Effectiveness
        effectiveness = 0.0
        if f.status == "PASS":
            # If evidence is uploaded, effectiveness is 100%, else 80%
            effectiveness = 1.0 if len(f.evidence_links) > 0 else 0.8
        elif f.status == "PARTIALLY_COMPLIANT":
            effectiveness = 0.5
        else:
            effectiveness = 0.0
            
        f.control_effectiveness = effectiveness
        
        # Risk exception check (Aging Exception)
        aging_exception = 1.0 # default: no exception active (fully computed)
        if f.risk_accepted:
            if not f.risk_exception_expiry or f.risk_exception_expiry > now:
                aging_exception = 0.0 # Residual risk is deferred/accepted (0 risk contribution)
                
        # Residual risk formula: Inherent * (1 - Effectiveness * Exception)
        residual = inherent * (1.0 - effectiveness) * aging_exception
        f.residual_risk = residual
        
        # Exclude N/A from totals
        if f.status != "NOT_APPLICABLE":
            total_inherent += inherent
            total_residual += residual
            
    # Calculate Overall Device Risk Rating (0-100)
    risk_score = 0.0
    if total_inherent > 0:
        risk_score = min(100.0, (total_residual / total_inherent) * 100)
        
    assessment.risk_score = risk_score
    db.commit()


# --- ATTACK SURFACE MANAGEMENT ENGINE ---
def calculate_attack_surface(db: Session, assessment_id: int) -> float:
    """
    Computes Tizen device Attack Surface Score (0-100) based on failed
    peripheral, network, and development port control configurations.
    """
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    score = 0.0
    # Map failed controls to specific attack surface weights
    exposure_rules = {
        "UTSCF-PIO-01": 15.0, # USB Debugging / SDB active
        "UTSCF-PIO-02": 10.0, # USB mounting allowed
        "UTSCF-NCS-03": 15.0, # Bluetooth Discoverable
        "UTSCF-NCS-05": 20.0, # SSH/Telnet enabled
        "UTSCF-BHS-01": 15.0, # Secure Boot disabled
        "UTSCF-PVM-01": 15.0  # Outdated firmware (firmware exploits)
    }
    
    for f in findings:
        cid = f.control.control_id
        if f.status == "FAIL":
            if cid in exposure_rules:
                score += exposure_rules[cid]
            elif cid.startswith("UTSCF-NCS") or cid.startswith("UTSCF-PIO"):
                # Minor network/peripheral failures
                score += 4.0
                
    return min(100.0, score)


# --- DRIFT DETECTION ENGINE ---
def detect_configuration_drift(db: Session, device_id: int, new_assessment_id: int) -> list:
    """
    Compares the newly completed compliance findings with the prior audit findings,
    emits configuration drift rows, and generates system alerts.
    """
    # Find prior assessment
    prior_assessment = db.query(Assessment)\
        .filter(Assessment.device_id == device_id, Assessment.id != new_assessment_id, Assessment.status == "Completed")\
        .order_by(Assessment.created_at.desc()).first()
        
    drifts = []
    if not prior_assessment:
        return drifts # No prior completed audits for comparison
        
    prior_findings = {f.control.control_id: f.status for f in prior_assessment.findings}
    new_findings = db.query(Finding).filter(Finding.assessment_id == new_assessment_id).all()
    
    for nf in new_findings:
        cid = nf.control.control_id
        prior_status = prior_findings.get(cid)
        
        # Check if status degraded (e.g. PASS -> FAIL, PASS -> PARTIAL, PARTIAL -> FAIL)
        if prior_status and prior_status != nf.status:
            is_degraded = False
            if prior_status == "PASS" and nf.status in ["FAIL", "PARTIALLY_COMPLIANT"]:
                is_degraded = True
            elif prior_status == "PARTIALLY_COMPLIANT" and nf.status == "FAIL":
                is_degraded = True
                
            if is_degraded:
                drift = ConfigDrift(
                    device_id=device_id,
                    control_id=cid,
                    old_value=prior_status,
                    new_value=nf.status
                )
                db.add(drift)
                drifts.append(drift)
                
                # Emit notification
                notif = Notification(
                    user_id=new_findings[0].assessment.assessor_id or 1,
                    type="DRIFT",
                    message=f"Configuration Drift detected on control {cid} ({nf.control.name}). Status degraded from {prior_status} to {nf.status}."
                )
                db.add(notif)
                
    db.commit()
    return drifts


# --- RECOMMENDATION & SMART PRIORITIZATION ENGINE ---
def get_prioritized_recommendations(db: Session, assessment_id: int) -> dict:
    """
    Generates intelligent prioritized recommendations for failed controls.
    Priority Score = CriticalityWeight * ResidualRisk * Exploitability * ControlWeight * AttackSurface
    """
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return {}
        
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    criticality_multiplier = {"HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}
    severity_exploitability = {"CRITICAL": 4.0, "HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}
    
    bc = criticality_multiplier.get(device.business_criticality, 2.0)
    as_score = assessment.attack_surface_score or 50.0
    
    failed_findings = [f for f in findings if f.status in ["FAIL", "PARTIALLY_COMPLIANT"]]
    remediation_roadmap = {
        "immediate": [],
        "short_term": [],
        "medium_term": [],
        "long_term": []
    }
    
    for f in failed_findings:
        ctrl = f.control
        exploitability = severity_exploitability.get(ctrl.severity, 2.0)
        
        # Priority formula: InherentRisk * Exploitability * AttackSurfaceIndex
        priority_score = f.residual_risk * exploitability * (as_score / 10.0)
        
        # Load structured policy remediation parameters
        remediation_data = {}
        try:
            remediation_data = json.loads(ctrl.remediation_guide) if ctrl.remediation_guide else {}
        except Exception:
            remediation_data = {}
            
        rec = {
            "control_id": ctrl.control_id,
            "name": ctrl.name,
            "domain": ctrl.domain,
            "severity": ctrl.severity,
            "priority_score": round(priority_score, 2),
            "business_impact": remediation_data.get("business_impact", "Allows unapproved execution parameters on subsystem components."),
            "technical_impact": remediation_data.get("technical_impact", "Allows bypass of Smack security rules or Cynara authorizations."),
            "recommended_fix": remediation_data.get("fix_steps", "Audit configuration settings and restore to locked profiles."),
            "validation_steps": remediation_data.get("validation_steps", "Run verification commands locally on the Tizen console."),
            "cost": remediation_data.get("cost", "LOW"),
            "difficulty": "Medium" if ctrl.severity in ["HIGH", "CRITICAL"] else "Low",
            "time_to_remediate": f"{remediation_data.get('estimated_time_hours', 2)} hours",
            "cves": ctrl.related_cves or "N/A",
            "mitre": ctrl.related_mitre_techniques or "N/A",
            "compliance_gain": round((ctrl.control_weight / sum(c.control_weight for c in findings if c.status != "NOT_APPLICABLE")) * 100, 2)
        }
        
        # Route based on priority score thresholds
        if priority_score >= 80:
            remediation_roadmap["immediate"].append(rec)
        elif priority_score >= 40:
            remediation_roadmap["short_term"].append(rec)
        elif priority_score >= 15:
            remediation_roadmap["medium_term"].append(rec)
        else:
            remediation_roadmap["long_term"].append(rec)
            
    # Sort lists inside roadmap by priority score descending
    for key in remediation_roadmap:
        remediation_roadmap[key] = sorted(remediation_roadmap[key], key=lambda x: x["priority_score"], reverse=True)
        
    return remediation_roadmap


# --- COMPLIANCE SIMULATOR ---
def simulate_improvements(db: Session, assessment_id: int, simulations: dict) -> dict:
    """
    Predicts the GRC metrics (Compliance %, Residual Risk, Posture, and Attack Surface)
    resulting from fixing selected configurations without committing changes.
    simulations: dict containing boolean values for simulated fixes (e.g. {"fix_usb_debugging": true, "enable_secure_boot": true})
    """
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return {}
        
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    
    # Deep copy findings simulation
    simulated_statuses = {}
    for f in findings:
        simulated_statuses[f.control.control_id] = f.status
        
    # Apply simulated fixes
    if simulations.get("fix_firmware"):
        simulated_statuses["UTSCF-PVM-01"] = "PASS"
        simulated_statuses["UTSCF-PVM-02"] = "PASS"
    if simulations.get("fix_secure_boot"):
        simulated_statuses["UTSCF-BHS-01"] = "PASS"
    if simulations.get("fix_usb"):
        simulated_statuses["UTSCF-PIO-01"] = "PASS"
        simulated_statuses["UTSCF-PIO-02"] = "PASS"
    if simulations.get("fix_bluetooth"):
        simulated_statuses["UTSCF-NCS-03"] = "PASS"
        simulated_statuses["UTSCF-NCS-04"] = "PASS"
    if simulations.get("fix_ssh"):
        simulated_statuses["UTSCF-NCS-05"] = "PASS"
        
    # Re-run scoring formulas on simulated statuses
    SEVERITY_WEIGHTS = {"CRITICAL": 4.0, "HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}
    SEVERITY_INHERENT_RISK = {"CRITICAL": 10.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0}
    criticality_map = {"HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}
    bc = criticality_map.get(device.business_criticality, 2.0)
    
    total_weight = 0.0
    weighted_compliance = 0.0
    total_inherent = 0.0
    total_residual = 0.0
    
    # For patch compliance simulation
    patch_total = 0
    patch_passed = 0
    
    # For evidence completeness simulation
    failed_or_partial_count = 0
    evidence_count = 0
    
    # For attack surface simulation
    simulated_as_score = 0.0
    exposure_rules = {
        "UTSCF-PIO-01": 15.0,
        "UTSCF-PIO-02": 10.0,
        "UTSCF-NCS-03": 15.0,
        "UTSCF-NCS-05": 20.0,
        "UTSCF-BHS-01": 15.0,
        "UTSCF-PVM-01": 15.0
    }
    
    for f in findings:
        cid = f.control.control_id
        status = simulated_statuses[cid]
        ctrl = f.control
        
        weight = SEVERITY_WEIGHTS.get(ctrl.severity, 1.0)
        inherent = SEVERITY_INHERENT_RISK.get(ctrl.severity, 2.0) * ctrl.control_weight * bc
        
        status_weight = 0.0
        if status == "PASS":
            status_weight = 1.0
        elif status == "PARTIALLY_COMPLIANT":
            status_weight = 0.5
        elif status == "FAIL":
            status_weight = 0.0
            
        if status != "NOT_APPLICABLE":
            total_weight += weight
            weighted_compliance += status_weight * weight
            total_inherent += inherent
            
            # Simulated Residual Risk calculation (effectiveness = 1.0 for simulated passes)
            eff = 1.0 if status == "PASS" else 0.5 if status == "PARTIALLY_COMPLIANT" else 0.0
            total_residual += inherent * (1.0 - eff)
            
        # Patch calculations
        if cid.startswith("UTSCF-PVM"):
            patch_total += 1
            if status == "PASS":
                patch_passed += 1
                
        # Evidence calculations
        if status in ["FAIL", "PARTIALLY_COMPLIANT"]:
            failed_or_partial_count += 1
            if len(f.evidence_links) > 0:
                evidence_count += 1
                
        # Attack Surface calculations
        if status == "FAIL":
            if cid in exposure_rules:
                simulated_as_score += exposure_rules[cid]
            elif cid.startswith("UTSCF-NCS") or cid.startswith("UTSCF-PIO"):
                simulated_as_score += 4.0
                
    sim_as_score = min(100.0, simulated_as_score)
    sim_compliance = (weighted_compliance / total_weight) * 100 if total_weight > 0 else 100.0
    sim_risk = (total_residual / total_inherent) * 100 if total_inherent > 0 else 0.0
    sim_patch = (patch_passed / patch_total) * 100 if patch_total > 0 else 100.0
    sim_evidence = (evidence_count / failed_or_partial_count) * 100 if failed_or_partial_count > 0 else 100.0
    
    # Posture Score simulation
    sim_posture = (
        0.35 * sim_compliance +
        0.25 * (100.0 - sim_risk) +
        0.15 * sim_patch +
        0.15 * sim_evidence +
        0.10 * (100.0 - sim_as_score)
    )
    
    return {
        "current": {
            "compliance": round(assessment.compliance_percentage, 2),
            "risk": round(assessment.risk_score, 2),
            "posture": round(assessment.posture_score or 0.0, 2),
            "attack_surface": round(assessment.attack_surface_score or 0.0, 2)
        },
        "predicted": {
            "compliance": round(sim_compliance, 2),
            "risk": round(sim_risk, 2),
            "posture": round(sim_posture, 2),
            "attack_surface": round(sim_as_score, 2)
        },
        "improvements": {
            "compliance_gain": round(sim_compliance - assessment.compliance_percentage, 2),
            "risk_reduction": round(assessment.risk_score - sim_risk, 2),
            "posture_gain": round(sim_posture - (assessment.posture_score or 0.0), 2),
            "attack_surface_reduction": round((assessment.attack_surface_score or 0.0) - sim_as_score, 2)
        }
    }
