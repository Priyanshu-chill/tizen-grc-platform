import os
import json
import datetime
from sqlalchemy.orm import Session
from database import engine, Base, SessionLocal
from models import Organization, Site, Building, DeviceGroup, User, Device, SecurityControl, Assessment, Finding
from auth import get_password_hash
from policies import generate_130_policies, write_policies_to_disk

def seed_database(db: Session):
    """Seed database with Orgs, Sites, Buildings, Device Groups, RBAC Users, and 130 Policy-as-Code controls."""
    
    # 1. Create Organization
    org = db.query(Organization).filter(Organization.code == "SEC-ENT").first()
    if not org:
        org = Organization(name="Samsung Enterprise Solutions", code="SEC-ENT")
        db.add(org)
        db.commit()
        db.refresh(org)
        print(f"Created organization: {org.name}")
    
    # 2. Create Sites
    seoul_site = db.query(Site).filter(Site.name == "Seoul R&D Center").first()
    if not seoul_site:
        seoul_site = Site(name="Seoul R&D Center", city="Seoul", country="South Korea", organization_id=org.id)
        db.add(seoul_site)
        
    sj_site = db.query(Site).filter(Site.name == "San Jose Lab").first()
    if not sj_site:
        sj_site = Site(name="San Jose Lab", city="San Jose", country="USA", organization_id=org.id)
        db.add(sj_site)
        
    db.commit()
    seoul_site = db.query(Site).filter(Site.name == "Seoul R&D Center").first()
    sj_site = db.query(Site).filter(Site.name == "San Jose Lab").first()
    
    # 3. Create Buildings (New in v3.0)
    seoul_building = db.query(Building).filter(Building.name == "Building A").first()
    if not seoul_building:
        seoul_building = Building(name="Building A", site_id=seoul_site.id)
        db.add(seoul_building)
        
    sj_building = db.query(Building).filter(Building.name == "Building B").first()
    if not sj_building:
        sj_building = Building(name="Building B", site_id=sj_site.id)
        db.add(sj_building)
        
    db.commit()
    seoul_building = db.query(Building).filter(Building.name == "Building A").first()
    sj_building = db.query(Building).filter(Building.name == "Building B").first()

    # 4. Create Device Groups (New in v3.0)
    seoul_group = db.query(DeviceGroup).filter(DeviceGroup.name == "Signage Displays").first()
    if not seoul_group:
        seoul_group = DeviceGroup(name="Signage Displays", building_id=seoul_building.id)
        db.add(seoul_group)
        
    sj_group = db.query(DeviceGroup).filter(DeviceGroup.name == "Wearable Terminals").first()
    if not sj_group:
        sj_group = DeviceGroup(name="Wearable Terminals", building_id=sj_building.id)
        db.add(sj_group)
        
    db.commit()
    seoul_group = db.query(DeviceGroup).filter(DeviceGroup.name == "Signage Displays").first()
    sj_group = db.query(DeviceGroup).filter(DeviceGroup.name == "Wearable Terminals").first()

    # 5. Create Users (RBAC: 7 Roles)
    users_to_create = [
        ("superadmin", "superadmin@utsgrcp.org", "Super Administrator", None),
        ("orgadmin", "orgadmin@samsung.com", "Organization Administrator", org.id),
        ("secadmin", "secadmin@samsung.com", "Security Administrator", org.id),
        ("officer", "compliance@samsung.com", "Compliance Officer", org.id),
        ("auditor", "auditor@audit.com", "Auditor", org.id),
        ("analyst", "analyst@samsung.com", "Security Analyst", org.id),
        ("readonly", "readonly@samsung.com", "Read-only User", org.id)
    ]
    
    for username, email, role, org_id in users_to_create:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            user = User(
                username=username,
                email=email,
                role=role,
                organization_id=org_id,
                hashed_password=get_password_hash("password123"),
                is_active=True
            )
            db.add(user)
            print(f"Created user {username} with role {role}")
    db.commit()

    # 6. Create Devices (Linked to DeviceGroup, with criticality)
    devices_to_create = [
        ("Seoul-Signage-01", "QM55R Smart Signage", "QM55R-2026-X123", "T-MS12WWD-1004.2", "Active", "00:11:22:33:44:55", "192.168.10.45", "HIGH", 5, '["SignageController", "AdPlayer"]', '["SamsungSignageRoot"]', seoul_group.id),
        ("Seoul-SmartTV-02", "QN65Q Smart TV", "QN65Q-2026-Y456", "T-KTM2DEUC-2210.1", "Active", "00:11:22:AA:BB:CC", "192.168.10.46", "MEDIUM", 3, '["WebBrowser", "ConferenceCast"]', '["SamsungTVRoot"]', seoul_group.id),
        ("SJ-Wearable-03", "Gear S4 Active Watch", "GEARS4-2026-Z789", "R800XXU1CSE1", "Active", "AA:BB:CC:DD:EE:FF", "10.0.2.115", "HIGH", 4, '["LogisticsTracker", "EmergencyAlert"]', '["SamsungWearableRoot"]', sj_group.id)
    ]
    
    for name, model, serial, fw, status, mac, ip, crit, importance, apps, certs, group_id in devices_to_create:
        device = db.query(Device).filter(Device.serial_number == serial).first()
        if not device:
            device = Device(
                name=name,
                model=model,
                serial_number=serial,
                firmware_version=fw,
                lifecycle_status=status,
                mac_address=mac,
                ip_address=ip,
                business_criticality=crit,
                device_importance=importance,
                installed_applications=apps,
                certificates=certs,
                device_group_id=group_id
            )
            db.add(device)
            print(f"Registered Tizen device: {name}")
    db.commit()

    # 7. Write Policy-as-Code files to disk
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    policies_dir = os.path.join(backend_dir, "policies")
    write_policies_to_disk(policies_dir)

    # 8. Seed Security Controls in DB
    controls = generate_130_policies()
    controls_seeded = 0
    for p in controls:
        existing = db.query(SecurityControl).filter(SecurityControl.control_id == p["control_id"]).first()
        if not existing:
            ctrl = SecurityControl(
                control_id=p["control_id"],
                domain=p["domain"],
                category=p["category"],
                name=p["name"],
                description=p["description"],
                security_objective=p["security_objective"],
                business_justification=p["business_justification"],
                severity=p["severity"],
                control_weight=p["control_weight"],
                validation_type=p["validation_type"],
                expected_value=p["expected_value"],
                verification_logic=p["verification_logic"],
                remediation_guide=p["remediation_guide"],
                standards_mapping=json.dumps(p["standards_mapping"]),
                related_cves=p["related_cves"],
                related_mitre_techniques=p["related_mitre_techniques"],
                policy_owner=p["policy_owner"],
                review_frequency_days=p["review_frequency_days"]
            )
            db.add(ctrl)
            controls_seeded += 1
            
    db.commit()
    print(f"Database Seeding: Inserted {controls_seeded} controls into DB controls table.")

if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        seed_database(session)
    finally:
        session.close()
