from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Any
from datetime import datetime

# --- Token Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str
    organization_id: Optional[int] = None

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


# --- User Schemas ---
class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str
    is_active: bool = True
    organization_id: Optional[int] = None

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None

class UserOut(UserBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True


# --- Organization Schemas ---
class OrganizationBase(BaseModel):
    name: str
    code: str

class OrganizationCreate(OrganizationBase):
    pass

class OrganizationOut(OrganizationBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True


# --- Site & Building & Group Schemas ---
class SiteBase(BaseModel):
    name: str
    city: Optional[str] = None
    country: Optional[str] = None
    organization_id: int

class SiteCreate(SiteBase):
    pass

class SiteOut(SiteBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True

class BuildingBase(BaseModel):
    name: str
    site_id: int

class BuildingCreate(BuildingBase):
    pass

class BuildingOut(BuildingBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True

class DeviceGroupBase(BaseModel):
    name: str
    building_id: int

class DeviceGroupCreate(DeviceGroupBase):
    pass

class DeviceGroupOut(DeviceGroupBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True


# --- Device Schemas ---
class DeviceBase(BaseModel):
    name: str
    model: str
    serial_number: str
    firmware_version: str
    tizen_version: str = "6.0"
    lifecycle_status: str = "Active"
    mac_address: Optional[str] = None
    ip_address: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    business_criticality: str = "MEDIUM"
    device_importance: int = 3
    installed_applications: str = "[]"
    certificates: str = "[]"
    device_group_id: int

class DeviceCreate(DeviceBase):
    pass

class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    tizen_version: Optional[str] = None
    lifecycle_status: Optional[str] = None
    mac_address: Optional[str] = None
    ip_address: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    business_criticality: Optional[str] = None
    device_importance: Optional[int] = None
    installed_applications: Optional[str] = None
    certificates: Optional[str] = None
    device_group_id: Optional[int] = None

class DeviceOut(DeviceBase):
    id: int
    last_seen: datetime
    created_at: datetime

    class Config:
        orm_mode = True


# --- Security Control Schemas ---
class SecurityControlOut(BaseModel):
    id: int
    control_id: str
    domain: str
    category: Optional[str] = None
    name: str
    description: Optional[str] = None
    security_objective: Optional[str] = None
    business_justification: Optional[str] = None
    severity: str
    control_weight: float
    validation_type: str
    expected_value: Optional[str] = None
    verification_logic: Optional[str] = None
    remediation_guide: Optional[str] = None
    standards_mapping: Optional[str] = None
    related_cves: Optional[str] = None
    related_mitre_techniques: Optional[str] = None
    policy_owner: Optional[str] = None
    review_frequency_days: int

    class Config:
        orm_mode = True


# --- Evidence Schemas ---
class EvidenceOut(BaseModel):
    id: int
    assessment_id: int
    finding_id: Optional[int] = None
    file_name: str
    file_path: str
    file_type: Optional[str] = None
    sha256_hash: Optional[str] = None
    integrity_status: Optional[str] = "Verified"
    uploaded_by: Optional[int] = None
    uploaded_at: datetime

    class Config:
        orm_mode = True


# --- Finding Schemas ---
class FindingUpdate(BaseModel):
    status: str  # PASS, FAIL, PARTIALLY_COMPLIANT, NOT_APPLICABLE
    comments: Optional[str] = None

class RiskExceptionInput(BaseModel):
    risk_accepted: bool
    risk_exception_reason: Optional[str] = None
    risk_exception_expiry_days: Optional[int] = None

class WorkflowAssignInput(BaseModel):
    assigned_to: int

class FindingOut(BaseModel):
    id: int
    assessment_id: int
    control_id: int
    control: SecurityControlOut
    status: str
    likelihood: float
    impact: float
    inherent_risk: float
    residual_risk: float
    control_effectiveness: float
    comments: Optional[str] = None
    workflow_status: str
    assigned_to: Optional[int] = None
    assigned_user: Optional[UserOut] = None
    risk_accepted: bool
    risk_exception_reason: Optional[str] = None
    risk_exception_expiry: Optional[datetime] = None
    risk_owner: Optional[int] = None
    risk_owner_user: Optional[UserOut] = None
    updated_at: datetime
    evidence_links: List[EvidenceOut] = []

    class Config:
        orm_mode = True


# --- Assessment Schemas ---
class AssessmentCreate(BaseModel):
    device_id: int

class AssessmentOut(BaseModel):
    id: int
    device_id: int
    device: DeviceOut
    assessor_id: Optional[int] = None
    assessor: Optional[UserOut] = None
    status: str
    compliance_percentage: float
    risk_score: float
    posture_score: float
    attack_surface_score: float
    maturity_level: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class AssessmentDetailOut(AssessmentOut):
    findings: List[FindingOut] = []

    class Config:
        orm_mode = True


# --- Config Drift Schemas ---
class ConfigDriftOut(BaseModel):
    id: int
    device_id: int
    control_id: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    timestamp: datetime

    class Config:
        orm_mode = True


# --- Notification Schemas ---
class NotificationOut(BaseModel):
    id: int
    user_id: int
    type: str
    message: str
    is_read: bool
    created_at: datetime

    class Config:
        orm_mode = True


# --- Historical Analytics Schemas ---
class HistoricalAnalyticsOut(BaseModel):
    id: int
    device_id: int
    timestamp: datetime
    compliance_percentage: float
    risk_score: float
    posture_score: float
    attack_surface_score: float
    mttr_days: float
    drift_count: int

    class Config:
        orm_mode = True


# --- Simulator Input Schemas ---
class SimulationInput(BaseModel):
    fix_firmware: bool = False
    fix_secure_boot: bool = False
    fix_usb: bool = False
    fix_bluetooth: bool = False
    fix_ssh: bool = False


# --- Dashboard Stats Schemas ---
class DomainCompliance(BaseModel):
    domain: str
    compliance_percentage: float
    failed_count: int
    passed_count: int

class DashboardStats(BaseModel):
    overall_compliance: float
    average_risk_score: float
    average_posture_score: float
    average_attack_surface: float
    total_devices: int
    compliant_devices: int
    partially_compliant_devices: int
    non_compliant_devices: int
    active_assessments: int
    domain_compliance: List[DomainCompliance]
    top_failed_controls: List[Any]
    findings_by_severity: Any
    risk_distribution: Any
    recent_assessments: List[AssessmentOut]
    drift_count_total: int
    active_alerts: List[NotificationOut]
