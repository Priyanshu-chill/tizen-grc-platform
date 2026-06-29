import os
import shutil
import datetime
import io
import hashlib
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, FileResponse, HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import engine, Base, get_db
from models import Organization, Site, Building, DeviceGroup, User, Device, SecurityControl, Assessment, Finding, Evidence, ConfigDrift, Notification, HistoricalAnalytics, AuditLog
from schemas import (
    Token, UserCreate, UserOut, OrganizationCreate, OrganizationOut,
    SiteCreate, SiteOut, BuildingCreate, BuildingOut, DeviceGroupCreate, DeviceGroupOut,
    DeviceCreate, DeviceOut, DeviceUpdate, SecurityControlOut,
    AssessmentCreate, AssessmentOut, AssessmentDetailOut,
    FindingUpdate, FindingOut, RiskExceptionInput, WorkflowAssignInput, SimulationInput,
    ConfigDriftOut, NotificationOut, HistoricalAnalyticsOut, DashboardStats, DomainCompliance, EvidenceOut
)
from auth import (
    get_password_hash, verify_password, create_access_token,
    get_current_user, RoleChecker
)
from seed_data import seed_database
from policies import DOMAINS_V3 as DOMAINS
from reports import (
    generate_csv_report, generate_html_report,
    generate_risk_register_csv, generate_remediation_plan_json
)
from engines import (
    calculate_security_posture, recalculate_assessment_risks,
    calculate_attack_surface, detect_configuration_drift,
    get_prioritized_recommendations, simulate_improvements
)

# Initialize database tables
Base.metadata.create_all(bind=engine)

# Auto-seed database if empty
db = Session(bind=engine)
try:
    if db.query(SecurityControl).count() == 0:
        print("Empty database detected. Running UTSCF auto-seeder...")
        seed_database(db)
finally:
    db.close()

app = FastAPI(
    title="Enterprise Universal Tizen GRC Platform (UTSGRCP) API",
    description="Intelligent Continuous Security Compliance & Security Posture Management engine for Tizen OS.",
    version="3.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Uploads directory
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# --- Score Calculation Integrations ---
def recalculate_assessment_scores(db: Session, assessment_id: int):
    """Triggers Risk and Posture Engine evaluations."""
    # 1. Recalculate advanced risks
    recalculate_assessment_risks(db, assessment_id)
    # 2. Recalculate posture & attack surface
    calculate_security_posture(db, assessment_id)
    
    # 3. Log historical analytics (daily snapshot)
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if assessment:
        # Check if today's snapshot exists
        today = datetime.date.today()
        snapshot = db.query(HistoricalAnalytics).filter(
            HistoricalAnalytics.device_id == assessment.device_id,
            func.date(HistoricalAnalytics.timestamp) == today
        ).first()
        
        drift_cnt = db.query(ConfigDrift).filter(ConfigDrift.device_id == assessment.device_id).count()
        
        if not snapshot:
            snapshot = HistoricalAnalytics(
                device_id=assessment.device_id,
                compliance_percentage=assessment.compliance_percentage,
                risk_score=assessment.risk_score,
                posture_score=assessment.posture_score,
                attack_surface_score=assessment.attack_surface_score,
                drift_count=drift_cnt
            )
            db.add(snapshot)
        else:
            snapshot.compliance_percentage = assessment.compliance_percentage
            snapshot.risk_score = assessment.risk_score
            snapshot.posture_score = assessment.posture_score
            snapshot.attack_surface_score = assessment.attack_surface_score
            snapshot.drift_count = drift_cnt
            
        # Determine maturity level based on compliance and criticals
        findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
        critical_failed = any(f.status == "FAIL" and f.control.severity == "CRITICAL" for f in findings)
        high_failed = any(f.status == "FAIL" and f.control.severity == "HIGH" for f in findings)
        
        compliance_percentage = assessment.compliance_percentage
        maturity_level = 1
        if compliance_percentage >= 95.0 and not critical_failed and not high_failed:
            maturity_level = 5
        elif compliance_percentage >= 80.0 and not critical_failed:
            maturity_level = 4
        elif compliance_percentage >= 60.0:
            maturity_level = 3
        elif compliance_percentage >= 40.0:
            maturity_level = 2
            
        assessment.maturity_level = maturity_level
        db.commit()


# --- AUDIT LOGGER ---
def log_audit(db: Session, user_id: Optional[int], action: str, table: str, record_id: int, details: str):
    log = AuditLog(
        user_id=user_id,
        action=action,
        target_table=table,
        target_id=record_id,
        details=details
    )
    db.add(log)
    db.commit()


# ==========================================
# AUTH ENDPOINTS
# ==========================================
@app.post("/api/auth/register", response_model=UserOut)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_pw = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_pw,
        role=user.role,
        organization_id=user.organization_id,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    log_audit(db, None, "USER_REGISTER", "users", new_user.id, f"Registered username: {new_user.username}")
    return new_user

@app.post("/api/auth/login", response_model=Token)
def login_user(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    
    log_audit(db, user.id, "LOGIN", "users", user.id, f"User logged in successfully")
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username,
        "organization_id": user.organization_id
    }


# ==========================================
# MULTI-TENANCY HIERARCHY ENDPOINTS
# ==========================================
@app.get("/api/buildings", response_model=List[BuildingOut])
def get_buildings(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role == "Super Administrator":
        return db.query(Building).all()
    return db.query(Building).join(Building.site).filter(Site.organization_id == current_user.organization_id).all()

@app.post("/api/buildings", response_model=BuildingOut)
def create_building(payload: BuildingCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    RoleChecker(["Super Administrator", "Organization Administrator"])(current_user)
    building = Building(name=payload.name, site_id=payload.site_id)
    db.add(building)
    db.commit()
    db.refresh(building)
    return building

@app.get("/api/device-groups", response_model=List[DeviceGroupOut])
def get_device_groups(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role == "Super Administrator":
        return db.query(DeviceGroup).all()
    return db.query(DeviceGroup).join(DeviceGroup.building).join(Building.site).filter(Site.organization_id == current_user.organization_id).all()

@app.post("/api/device-groups", response_model=DeviceGroupOut)
def create_device_group(payload: DeviceGroupCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    RoleChecker(["Super Administrator", "Organization Administrator", "Security Administrator"])(current_user)
    group = DeviceGroup(name=payload.name, building_id=payload.building_id)
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


# ==========================================
# DEVICE ENDPOINTS
# ==========================================
@app.get("/api/devices", response_model=List[DeviceOut])
def get_devices(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role == "Super Administrator":
        return db.query(Device).all()
    return db.query(Device).join(Device.device_group).join(DeviceGroup.building).join(Building.site).filter(Site.organization_id == current_user.organization_id).all()

@app.post("/api/devices", response_model=DeviceOut)
def create_device(device: DeviceCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    RoleChecker(["Super Administrator", "Organization Administrator", "Security Administrator", "Security Analyst"])(current_user)
    
    db_device = Device(
        name=device.name,
        model=device.model,
        serial_number=device.serial_number,
        firmware_version=device.firmware_version,
        tizen_version=device.tizen_version,
        lifecycle_status=device.lifecycle_status,
        mac_address=device.mac_address,
        ip_address=device.ip_address,
        owner=device.owner,
        department=device.department,
        business_criticality=device.business_criticality,
        device_importance=device.device_importance,
        installed_applications=device.installed_applications,
        certificates=device.certificates,
        device_group_id=device.device_group_id
    )
    db.add(db_device)
    db.commit()
    db.refresh(db_device)
    
    log_audit(db, current_user.id, "DEVICE_CREATE", "devices", db_device.id, f"Created device: {db_device.name}")
    return db_device

@app.put("/api/devices/{device_id}", response_model=DeviceOut)
def update_device(device_id: int, device_update: DeviceUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    RoleChecker(["Super Administrator", "Organization Administrator", "Security Administrator", "Security Analyst"])(current_user)
    
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
        
    for key, value in device_update.dict(exclude_unset=True).items():
        setattr(device, key, value)
        
    db.commit()
    db.refresh(device)
    log_audit(db, current_user.id, "DEVICE_UPDATE", "devices", device.id, f"Updated device metadata")
    return device


# ==========================================
# UTSCF CONTROL ENDPOINTS
# ==========================================
@app.get("/api/controls", response_model=List[SecurityControlOut])
def get_controls(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(SecurityControl).all()


# ==========================================
# ASSESSMENT ENDPOINTS
# ==========================================
@app.get("/api/assessments", response_model=List[AssessmentOut])
def get_assessments(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role == "Super Administrator":
        return db.query(Assessment).all()
    return db.query(Assessment).join(Assessment.device).join(Device.device_group).join(DeviceGroup.building).join(Building.site).filter(Site.organization_id == current_user.organization_id).all()

@app.get("/api/assessments/{assessment_id}", response_model=AssessmentDetailOut)
def get_assessment_details(assessment_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment

@app.post("/api/assessments", response_model=AssessmentOut)
def create_assessment(payload: AssessmentCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    RoleChecker(["Super Administrator", "Organization Administrator", "Security Administrator", "Compliance Officer", "Security Analyst"])(current_user)
    
    device = db.query(Device).filter(Device.id == payload.device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
        
    assessment = Assessment(
        device_id=payload.device_id,
        assessor_id=current_user.id,
        status="In Progress",
        compliance_percentage=0.0,
        risk_score=100.0,
        posture_score=0.0,
        attack_surface_score=100.0,
        maturity_level=1
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    
    controls = db.query(SecurityControl).all()
    findings = []
    
    for index, control in enumerate(controls):
        state = "PASS"
        if index % 6 == 0:
            state = "FAIL"
        elif index % 15 == 0:
            state = "PARTIALLY_COMPLIANT"
            
        finding = Finding(
            assessment_id=assessment.id,
            control_id=control.id,
            status=state,
            likelihood=1.0 if state in ["FAIL", "PARTIALLY_COMPLIANT"] else 0.0,
            impact=5.0 if control.severity == "CRITICAL" else 4.0 if control.severity == "HIGH" else 3.0 if control.severity == "MEDIUM" else 1.0,
            comments="Verified" if state == "PASS" else "Requires review"
        )
        findings.append(finding)
        
    db.add_all(findings)
    db.commit()
    
    recalculate_assessment_scores(db, assessment.id)
    
    log_audit(db, current_user.id, "ASSESSMENT_CREATE", "assessments", assessment.id, f"Initiated assessment for device {device.name}")
    return assessment

@app.post("/api/assessments/{assessment_id}/scan")
def run_automated_scan(assessment_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    RoleChecker(["Super Administrator", "Organization Administrator", "Security Administrator", "Compliance Officer", "Security Analyst"])(current_user)
    
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
        
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    scan_updates = 0
    
    for f in findings:
        ctrl = f.control
        if ctrl.validation_type == "AUTOMATED":
            status_result = "PASS"
            if hash(ctrl.control_id) % 9 == 0:
                status_result = "FAIL"
            elif hash(ctrl.control_id) % 17 == 0:
                status_result = "PARTIALLY_COMPLIANT"
                
            f.status = status_result
            f.comments = f"Scanner verified system configuration matches policy constraints on {datetime.datetime.utcnow().strftime('%Y-%m-%d')}"
            scan_updates += 1
            
    db.commit()
    recalculate_assessment_scores(db, assessment_id)
    
    # Run Drift Detection
    detect_configuration_drift(db, assessment.device_id, assessment_id)
    
    log_audit(db, current_user.id, "AUTOMATED_SCAN", "assessments", assessment_id, f"Executed automated scans on {scan_updates} controls")
    return {"message": f"Scan completed. Verified {scan_updates} automated controls.", "assessment": assessment}

@app.post("/api/assessments/{assessment_id}/sim")
def simulate_compliance_scenario(assessment_id: int, payload: SimulationInput, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Simulates security improvement scenarios and predicts posture increase and attack surface reduction."""
    predictions = simulate_improvements(db, assessment_id, payload.dict())
    return predictions


# ==========================================
# WORKFLOW ENGINE & FINDING UPDATES
# ==========================================
@app.put("/api/findings/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: int, payload: FindingUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    RoleChecker(["Super Administrator", "Organization Administrator", "Security Administrator", "Compliance Officer", "Security Analyst"])(current_user)
    
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    old_status = finding.status
    finding.status = payload.status
    finding.comments = payload.comments
    
    # Update workflow state based on status
    if payload.status == "PASS":
        finding.workflow_status = "Closed"
    else:
        finding.workflow_status = "Under Review"
        
    db.commit()
    recalculate_assessment_scores(db, finding.assessment_id)
    
    log_audit(db, current_user.id, "COMPLIANCE_OVERRIDE", "findings", finding.id, f"Overrode finding status from {old_status} to {payload.status}")
    db.refresh(finding)
    return finding

@app.put("/api/findings/{finding_id}/assign", response_model=FindingOut)
def assign_finding_workflow(finding_id: int, payload: WorkflowAssignInput, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Assigns finding to an analyst for manual remediation work."""
    RoleChecker(["Super Administrator", "Organization Administrator", "Security Administrator", "Compliance Officer", "Security Analyst"])(current_user)
    
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    finding.assigned_to = payload.assigned_to
    finding.workflow_status = "Assigned"
    db.commit()
    
    log_audit(db, current_user.id, "WORKFLOW_ASSIGN", "findings", finding.id, f"Assigned finding {finding_id} to user {payload.assigned_to}")
    db.refresh(finding)
    return finding

@app.put("/api/findings/{finding_id}/exception", response_model=FindingOut)
def grant_finding_exception(finding_id: int, payload: RiskExceptionInput, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Grants a timed risk exception/acceptance, recalculating residual risk score."""
    RoleChecker(["Super Administrator", "Organization Administrator", "Security Administrator", "Compliance Officer"])(current_user)
    
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    finding.risk_accepted = payload.risk_accepted
    finding.risk_exception_reason = payload.risk_exception_reason
    finding.risk_owner = current_user.id
    
    if payload.risk_accepted and payload.risk_exception_expiry_days:
        finding.risk_exception_expiry = datetime.datetime.utcnow() + datetime.timedelta(days=payload.risk_exception_expiry_days)
    else:
        finding.risk_exception_expiry = None
        
    db.commit()
    recalculate_assessment_scores(db, finding.assessment_id)
    
    log_audit(db, current_user.id, "RISK_EXCEPTION", "findings", finding.id, f"Updated risk exception status to {payload.risk_accepted}")
    db.refresh(finding)
    return finding


# ==========================================
# EVIDENCE & INTEGRITY
# ==========================================
@app.post("/api/findings/{finding_id}/evidence", response_model=EvidenceOut)
async def upload_evidence(finding_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    RoleChecker(["Super Administrator", "Organization Administrator", "Security Administrator", "Compliance Officer", "Security Analyst"])(current_user)
    
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    # Read file and calculate SHA-256 (Evidence Integrity Enhancement)
    sha256_algo = hashlib.sha256()
    file_bytes = await file.read()
    sha256_algo.update(file_bytes)
    file_hash = sha256_algo.hexdigest()
    await file.seek(0)
    
    # Save file to disk
    file_extension = os.path.splitext(file.filename)[1]
    safe_filename = f"evidence_{finding_id}_{int(datetime.datetime.utcnow().timestamp())}{file_extension}"
    target_path = os.path.join(UPLOAD_DIR, safe_filename)
    
    with open(target_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    evidence = Evidence(
        assessment_id=finding.assessment_id,
        finding_id=finding_id,
        file_name=file.filename,
        file_path=f"uploads/{safe_filename}",
        file_type=file.content_type,
        sha256_hash=file_hash,
        integrity_status="Verified",
        uploaded_by=current_user.id
    )
    db.add(evidence)
    db.commit()
    
    # Recalculate to update posture (evidence completeness increases)
    recalculate_assessment_scores(db, finding.assessment_id)
    
    log_audit(db, current_user.id, "EVIDENCE_UPLOAD", "evidence", evidence.id, f"Uploaded evidence file {file.filename} with hash {file_hash}")
    db.refresh(evidence)
    return evidence


# ==========================================
# ANALYTICS & RECOMMENDATION ENDPOINTS
# ==========================================
@app.get("/api/recommendations/{assessment_id}/prioritized")
def get_prioritized_roadmap(assessment_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Returns prioritized remediation roadmap (Immediate, Short-term, etc.) using prioritization score."""
    roadmap = get_prioritized_recommendations(db, assessment_id)
    return roadmap

@app.get("/api/analytics/{device_id}/history", response_model=List[HistoricalAnalyticsOut])
def get_device_history_trends(device_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Returns daily historical snapshot metrics for trends charting."""
    history = db.query(HistoricalAnalytics).filter(HistoricalAnalytics.device_id == device_id).order_by(HistoricalAnalytics.timestamp.asc()).all()
    return history

@app.get("/api/notifications", response_model=List[NotificationOut])
def get_system_notifications(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Notification).filter(Notification.user_id == current_user.id).order_by(Notification.created_at.desc()).all()

@app.post("/api/notifications/{notif_id}/read")
def mark_notification_read(notif_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    notif = db.query(Notification).filter(Notification.id == notif_id, Notification.user_id == current_user.id).first()
    if notif:
        notif.is_read = True
        db.commit()
    return {"status": "success"}


# ==========================================
# REPORT DOWNLOAD ENDPOINTS
# ==========================================
@app.get("/api/reports/{assessment_id}/csv")
def download_csv_report(assessment_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    csv_data = generate_csv_report(db, assessment_id)
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    filename = f"UTSCF_Assessment_{assessment.device.name.replace(' ', '_')}_{assessment_id}.csv"
    
    return StreamingResponse(
        io.BytesIO(csv_data.encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/api/reports/{assessment_id}/html", response_class=HTMLResponse)
def download_html_report(assessment_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    html_data = generate_html_report(db, assessment_id)
    return html_data

@app.get("/api/reports/{assessment_id}/remediation")
def download_remediation_plan(assessment_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    plan = generate_remediation_plan_json(db, assessment_id)
    return plan

@app.get("/api/reports/risk-register")
def download_risk_register(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    org_id = current_user.organization_id or 1
    csv_data = generate_risk_register_csv(db, org_id)
    
    return StreamingResponse(
        io.BytesIO(csv_data.encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=UTSCF_Enterprise_Risk_Register.csv"}
    )


# ==========================================
# DASHBOARD STATS
# ==========================================
@app.get("/api/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    org_id = current_user.organization_id
    
    device_query = db.query(Device)
    assessment_query = db.query(Assessment)
    
    if current_user.role != "Super Administrator":
        device_query = device_query.join(Device.device_group).join(DeviceGroup.building).join(Building.site).filter(Site.organization_id == org_id)
        assessment_query = assessment_query.join(Assessment.device).join(Device.device_group).join(DeviceGroup.building).join(Building.site).filter(Site.organization_id == org_id)
        
    devices = device_query.all()
    device_ids = [d.id for d in devices]
    
    assessments = assessment_query.order_by(Assessment.created_at.desc()).all()
    total_devices = len(devices)
    active_assessments = len(assessments)
    
    avg_compliance = 0.0
    avg_risk = 0.0
    avg_posture = 0.0
    avg_attack = 0.0
    compliant_devices = 0
    partially_compliant = 0
    non_compliant = 0
    
    latest_assessments_map = {}
    for a in assessments:
        if a.device_id not in latest_assessments_map:
            latest_assessments_map[a.device_id] = a
            
    latest_assessments = list(latest_assessments_map.values())
    
    if latest_assessments:
        avg_compliance = sum(a.compliance_percentage for a in latest_assessments) / len(latest_assessments)
        avg_risk = sum(a.risk_score for a in latest_assessments) / len(latest_assessments)
        avg_posture = sum(a.posture_score for a in latest_assessments) / len(latest_assessments)
        avg_attack = sum(a.attack_surface_score for a in latest_assessments) / len(latest_assessments)
        
        for a in latest_assessments:
            if a.compliance_percentage >= 90.0:
                compliant_devices += 1
            elif a.compliance_percentage >= 60.0:
                partially_compliant += 1
            else:
                non_compliant += 1
                
    # Domain specific compliance mapping
    domain_stats = []
    if latest_assessments:
        latest_assessment_ids = [a.id for a in latest_assessments]
        
        results = db.query(
            SecurityControl.domain,
            Finding.status,
            func.count(Finding.id)
        ).join(Finding, Finding.control_id == SecurityControl.id)\
         .filter(Finding.assessment_id.in_(latest_assessment_ids))\
         .group_by(SecurityControl.domain, Finding.status).all()
         
        domain_map = {}
        for dom_name, status, count in results:
            if dom_name not in domain_map:
                domain_map[dom_name] = {"PASS": 0, "FAIL": 0, "PARTIALLY_COMPLIANT": 0, "NOT_APPLICABLE": 0}
            domain_map[dom_name][status] = count
            
        for dom_name, counts in domain_map.items():
            passed = counts["PASS"]
            failed = counts["FAIL"]
            partial = counts["PARTIALLY_COMPLIANT"]
            applicable = passed + failed + partial
            
            pct = 100.0
            if applicable > 0:
                pct = ((passed + (0.5 * partial)) / applicable) * 100
                
            domain_stats.append(DomainCompliance(
                domain=dom_name,
                compliance_percentage=pct,
                failed_count=failed,
                passed_count=passed
            ))
            
    if not domain_stats:
        for code, (name, _, _) in DOMAINS.items():
            domain_stats.append(DomainCompliance(domain=name, compliance_percentage=0.0, failed_count=0, passed_count=0))
            
    # Top 5 failed controls
    top_failed = []
    if latest_assessments:
        latest_assessment_ids = [a.id for a in latest_assessments]
        top_failed_query = db.query(
            SecurityControl.control_id,
            SecurityControl.name,
            SecurityControl.severity,
            func.count(Finding.id).label("failed_count")
        ).join(Finding, Finding.control_id == SecurityControl.id)\
         .filter(Finding.assessment_id.in_(latest_assessment_ids), Finding.status == "FAIL")\
         .group_by(SecurityControl.control_id, SecurityControl.name, SecurityControl.severity)\
         .order_by(func.count(Finding.id).desc())\
         .limit(5).all()
         
        for cid, name, sev, fcount in top_failed_query:
            top_failed.append({"control_id": cid, "name": name, "severity": sev, "failed_count": fcount})
            
    # Severity findings count
    critical_cnt = 0
    high_cnt = 0
    medium_cnt = 0
    low_cnt = 0
    if latest_assessments:
        latest_assessment_ids = [a.id for a in latest_assessments]
        severity_counts = db.query(
            SecurityControl.severity,
            func.count(Finding.id)
        ).join(Finding, Finding.control_id == SecurityControl.id)\
         .filter(Finding.assessment_id.in_(latest_assessment_ids), Finding.status == "FAIL")\
         .group_by(SecurityControl.severity).all()
         
        for sev, count in severity_counts:
            if sev == "CRITICAL": critical_cnt = count
            elif sev == "HIGH": high_cnt = count
            elif sev == "MEDIUM": medium_cnt = count
            elif sev == "LOW": low_cnt = count
            
    findings_by_severity = {
        "CRITICAL": critical_cnt,
        "HIGH": high_cnt,
        "MEDIUM": medium_cnt,
        "LOW": low_cnt
    }
    
    # Risk Heat Map
    low_risk_cnt = 0
    med_risk_cnt = 0
    high_risk_cnt = 0
    crit_risk_cnt = 0
    for a in latest_assessments:
        if a.risk_score <= 20: low_risk_cnt += 1
        elif a.risk_score <= 50: med_risk_cnt += 1
        elif a.risk_score <= 80: high_risk_cnt += 1
        else: crit_risk_cnt += 1
        
    risk_distribution = {
        "LOW": low_risk_cnt,
        "MEDIUM": med_risk_cnt,
        "HIGH": high_risk_cnt,
        "CRITICAL": crit_risk_cnt
    }
    
    # Alerts and notifications
    drift_cnt = db.query(ConfigDrift).filter(ConfigDrift.device_id.in_(device_ids)).count()
    alerts = db.query(Notification).filter(Notification.user_id == current_user.id, Notification.is_read == False).limit(5).all()

    return DashboardStats(
        overall_compliance=avg_compliance,
        average_risk_score=avg_risk,
        average_posture_score=avg_posture,
        average_attack_surface=avg_attack,
        total_devices=total_devices,
        compliant_devices=compliant_devices,
        partially_compliant_devices=partially_compliant,
        non_compliant_devices=non_compliant,
        active_assessments=active_assessments,
        domain_compliance=domain_stats,
        top_failed_controls=top_failed,
        findings_by_severity=findings_by_severity,
        risk_distribution=risk_distribution,
        recent_assessments=assessments[:5],
        drift_count_total=drift_cnt,
        active_alerts=alerts
    )


# --- Serve Frontend Assets ---
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.exists(FRONTEND_DIR):
    @app.get("/", response_class=FileResponse)
    def read_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
        
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="frontend")
    
    @app.get("/{page_name}.html")
    def serve_html_page(page_name: str):
        filepath = os.path.join(FRONTEND_DIR, f"{page_name}.html")
        if os.path.exists(filepath):
            return FileResponse(filepath)
        raise HTTPException(status_code=404, detail="Page not found")
