import datetime
from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Boolean, Text
from sqlalchemy.orm import relationship
from database import Base

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    code = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    sites = relationship("Site", back_populates="organization", cascade="all, delete-orphan")
    users = relationship("User", back_populates="organization")


class Site(Base):
    __tablename__ = "sites"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    city = Column(String, nullable=True)
    country = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="sites")
    buildings = relationship("Building", back_populates="site", cascade="all, delete-orphan")


class Building(Base):
    __tablename__ = "buildings"

    id = Column(Integer, primary_key=True, index=True)
    site_id = Column(Integer, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    site = relationship("Site", back_populates="buildings")
    device_groups = relationship("DeviceGroup", back_populates="building", cascade="all, delete-orphan")


class DeviceGroup(Base):
    __tablename__ = "device_groups"

    id = Column(Integer, primary_key=True, index=True)
    building_id = Column(Integer, ForeignKey("buildings.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    building = relationship("Building", back_populates="device_groups")
    devices = relationship("Device", back_populates="device_group", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="Read-only")  
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="users")
    assessments = relationship("Assessment", back_populates="assessor")
    audit_logs = relationship("AuditLog", back_populates="user")


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_group_id = Column(Integer, ForeignKey("device_groups.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    model = Column(String, nullable=False)  
    serial_number = Column(String, unique=True, index=True, nullable=False)
    firmware_version = Column(String, nullable=False)
    tizen_version = Column(String, default="6.0")
    lifecycle_status = Column(String, default="Active")  
    mac_address = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    owner = Column(String, nullable=True)
    department = Column(String, nullable=True)
    business_criticality = Column(String, default="MEDIUM")  # HIGH, MEDIUM, LOW
    device_importance = Column(Integer, default=3) # 1 (Low) to 5 (Critical)
    installed_applications = Column(Text, default="[]") # JSON string array
    certificates = Column(Text, default="[]") # JSON string array
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    device_group = relationship("DeviceGroup", back_populates="devices")
    assessments = relationship("Assessment", back_populates="device", cascade="all, delete-orphan")
    drifts = relationship("ConfigDrift", back_populates="device", cascade="all, delete-orphan")
    historical_analytics = relationship("HistoricalAnalytics", back_populates="device", cascade="all, delete-orphan")


class SecurityControl(Base):
    __tablename__ = "security_controls"

    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(String, unique=True, index=True, nullable=False)  
    domain = Column(String, nullable=False)  
    category = Column(String, nullable=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    security_objective = Column(Text, nullable=True)
    business_justification = Column(Text, nullable=True)
    severity = Column(String, default="MEDIUM")  
    control_weight = Column(Float, default=2.0)
    validation_type = Column(String, default="MANUAL")  
    expected_value = Column(Text, nullable=True)  
    verification_logic = Column(Text, nullable=True)
    remediation_guide = Column(Text, nullable=True) # JSON config instructions
    standards_mapping = Column(Text, default="{}") # JSON mapping ISO, NIST, etc.
    related_cves = Column(String, nullable=True) # comma-separated
    related_mitre_techniques = Column(String, nullable=True) # comma-separated
    policy_owner = Column(String, default="Super Admin")
    review_frequency_days = Column(Integer, default=90)


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    assessor_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String, default="In Progress")  
    compliance_percentage = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    posture_score = Column(Float, default=0.0)
    attack_surface_score = Column(Float, default=0.0)
    maturity_level = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Relationships
    device = relationship("Device", back_populates="assessments")
    assessor = relationship("User", back_populates="assessments")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="assessment", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    control_id = Column(Integer, ForeignKey("security_controls.id", ondelete="CASCADE"), nullable=False)
    status = Column(String, default="FAIL")  
    likelihood = Column(Float, default=1.0)
    impact = Column(Float, default=3.0)
    inherent_risk = Column(Float, default=0.0)
    residual_risk = Column(Float, default=0.0)
    control_effectiveness = Column(Float, default=0.0)
    comments = Column(Text, nullable=True)
    workflow_status = Column(String, default="Open") # Open, Assigned, Remediated, Closed
    assigned_to = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    risk_accepted = Column(Boolean, default=False)
    risk_exception_reason = Column(Text, nullable=True)
    risk_exception_expiry = Column(DateTime, nullable=True)
    risk_owner = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Relationships
    assessment = relationship("Assessment", back_populates="findings")
    control = relationship("SecurityControl")
    evidence_links = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    risk_owner_user = relationship("User", foreign_keys=[risk_owner])


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    file_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    file_type = Column(String, nullable=True)  
    sha256_hash = Column(String(64), nullable=True)
    integrity_status = Column(String(20), default="Verified") # Verified, Corrupted
    uploaded_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    uploaded_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    assessment = relationship("Assessment", back_populates="evidence")
    finding = relationship("Finding", back_populates="evidence_links")
    uploader = relationship("User")


class ConfigDrift(Base):
    __tablename__ = "config_drifts"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    control_id = Column(String, nullable=False)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    device = relationship("Device", back_populates="drifts")


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    type = Column(String, nullable=False) # DRIFT, HIGH_RISK, OUTDATED, REASSESSMENT_DUE
    message = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class HistoricalAnalytics(Base):
    __tablename__ = "historical_analytics"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    compliance_percentage = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    posture_score = Column(Float, default=0.0)
    attack_surface_score = Column(Float, default=0.0)
    mttr_days = Column(Float, default=0.0)
    drift_count = Column(Integer, default=0)

    # Relationships
    device = relationship("Device", back_populates="historical_analytics")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String, nullable=False)  
    target_table = Column(String, nullable=True)
    target_id = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="audit_logs")
