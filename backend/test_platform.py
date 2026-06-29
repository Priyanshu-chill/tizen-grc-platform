import unittest
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Organization, Site, Building, DeviceGroup, User, Device, SecurityControl, Assessment, Finding, ConfigDrift, Notification
from seed_data import seed_database
from main import recalculate_assessment_scores
from engines import (
    calculate_security_posture, recalculate_assessment_risks,
    calculate_attack_surface, detect_configuration_drift
)

class TestGRCEngine(unittest.TestCase):
    def setUp(self):
        # Create an in-memory SQLite database for testing
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        
        # Seed test database
        seed_database(self.session)
        
    def tearDown(self):
        self.session.close()
        Base.metadata.drop_all(self.engine)
        
    def test_database_seeding(self):
        """Verify that seeder successfully creates buildings, groups, and 130 UTSCF controls."""
        org = self.session.query(Organization).first()
        self.assertIsNotNone(org)
        self.assertEqual(org.code, "SEC-ENT")
        
        building = self.session.query(Building).first()
        self.assertIsNotNone(building)
        self.assertEqual(building.name, "Building A")
        
        group = self.session.query(DeviceGroup).first()
        self.assertIsNotNone(group)
        self.assertEqual(group.name, "Signage Displays")
        
        controls_count = self.session.query(SecurityControl).count()
        self.assertEqual(controls_count, 130, "Should seed exactly 130 security controls")
        
    def test_compliance_and_risk_math(self):
        """Test calculation of advanced inherent and residual risks based on weights."""
        device = self.session.query(Device).first()
        # Set business criticality for test predictability
        device.business_criticality = "HIGH" # Multiplier: 3.0
        self.session.commit()
        
        assessment = Assessment(
            device_id=device.id,
            status="In Progress",
            compliance_percentage=0.0,
            risk_score=100.0,
            maturity_level=1
        )
        self.session.add(assessment)
        self.session.commit()
        
        # Add 3 test controls:
        # - c1: CRITICAL (Weight 4.0) -> status PASS, no evidence (Effectiveness: 0.8)
        # - c2: HIGH (Weight 3.0) -> status FAIL (Effectiveness: 0.0)
        # - c3: MEDIUM (Weight 2.0) -> status PARTIALLY_COMPLIANT (Effectiveness: 0.5)
        c1 = SecurityControl(control_id="UTSCF-TST-01", domain="Test", name="C1", severity="CRITICAL", control_weight=4.0, validation_type="MANUAL")
        c2 = SecurityControl(control_id="UTSCF-TST-02", domain="Test", name="C2", severity="HIGH", control_weight=3.0, validation_type="MANUAL")
        c3 = SecurityControl(control_id="UTSCF-TST-03", domain="Test", name="C3", severity="MEDIUM", control_weight=2.0, validation_type="MANUAL")
        self.session.add_all([c1, c2, c3])
        self.session.commit()
        
        f1 = Finding(assessment_id=assessment.id, control_id=c1.id, status="PASS", comments="Verified")
        f2 = Finding(assessment_id=assessment.id, control_id=c2.id, status="FAIL", comments="Failed")
        f3 = Finding(assessment_id=assessment.id, control_id=c3.id, status="PARTIALLY_COMPLIANT", comments="Partial")
        self.session.add_all([f1, f2, f3])
        self.session.commit()
        
        recalculate_assessment_risks(self.session, assessment.id)
        
        # Expected Inherent Risks:
        # Impact: c1 (CRITICAL=5.0), c2 (HIGH=4.0), c3 (MEDIUM=3.0)
        # business_criticality = 3.0 (HIGH)
        # c1 inherent = 5.0 * 4.0 * 3.0 = 60.0
        # c2 inherent = 4.0 * 3.0 * 3.0 = 36.0
        # c3 inherent = 3.0 * 2.0 * 3.0 = 18.0
        # Total Inherent = 60 + 36 + 18 = 114.0
        self.assertEqual(f1.inherent_risk, 60.0)
        self.assertEqual(f2.inherent_risk, 36.0)
        self.assertEqual(f3.inherent_risk, 18.0)
        
        # Expected Residual Risks:
        # c1 effectiveness = 0.8 (PASS, no evidence) -> Residual = 60 * (1 - 0.8) = 12.0
        # c2 effectiveness = 0.0 (FAIL) -> Residual = 36.0
        # c3 effectiveness = 0.5 (PARTIAL) -> Residual = 18 * (1 - 0.5) = 9.0
        # Total Residual = 12.0 + 36.0 + 9.0 = 57.0
        # Risk Score % = (57.0 / 114.0) * 100 = 50.0%
        self.assertAlmostEqual(f1.residual_risk, 12.0, places=2)
        self.assertAlmostEqual(f2.residual_risk, 36.0, places=2)
        self.assertAlmostEqual(f3.residual_risk, 9.0, places=2)
        self.assertAlmostEqual(assessment.risk_score, 50.0, places=2)

    def test_risk_exception_aging(self):
        """Verify that active risk exceptions defer/mitigate the active residual risk score."""
        device = self.session.query(Device).first()
        assessment = Assessment(device_id=device.id, status="In Progress")
        self.session.add(assessment)
        self.session.commit()
        
        c1 = SecurityControl(control_id="UTSCF-EX-01", domain="Test", name="C1", severity="CRITICAL", control_weight=4.0, validation_type="MANUAL")
        self.session.add(c1)
        self.session.commit()
        
        f1 = Finding(assessment_id=assessment.id, control_id=c1.id, status="FAIL", comments="Failed")
        self.session.add(f1)
        self.session.commit()
        
        # Verify inherent risk matches failure before exception
        recalculate_assessment_risks(self.session, assessment.id)
        initial_risk = assessment.risk_score
        self.assertEqual(initial_risk, 100.0)
        
        # Apply Risk Exception (Active, non-expired)
        f1.risk_accepted = True
        f1.risk_exception_expiry = datetime.datetime.utcnow() + datetime.timedelta(days=30)
        self.session.commit()
        
        recalculate_assessment_risks(self.session, assessment.id)
        # Residual risk should go to 0 because the aging Exception is active
        self.assertEqual(f1.residual_risk, 0.0)
        self.assertEqual(assessment.risk_score, 0.0)

    def test_posture_and_attack_surface(self):
        """Test math of attack surface calculations and security posture scores."""
        device = self.session.query(Device).first()
        assessment = Assessment(
            device_id=device.id,
            status="In Progress",
            compliance_percentage=80.0,
            risk_score=20.0
        )
        self.session.add(assessment)
        self.session.commit()
        
        # Fetch pre-seeded controls representing open attack vectors:
        c1 = self.session.query(SecurityControl).filter(SecurityControl.control_id == "UTSCF-PIO-01").first()
        c2 = self.session.query(SecurityControl).filter(SecurityControl.control_id == "UTSCF-NCS-03").first()
        
        f1 = Finding(assessment_id=assessment.id, control_id=c1.id, status="FAIL")
        f2 = Finding(assessment_id=assessment.id, control_id=c2.id, status="FAIL")
        self.session.add_all([f1, f2])
        self.session.commit()
        
        # Verify Attack Surface
        as_score = calculate_attack_surface(self.session, assessment.id)
        self.assertEqual(as_score, 30.0) # 15 + 15 = 30
        
        # Verify Posture Score (no evidence uploaded)
        # posture = 0.35 * compliance (80) + 0.25 * (100 - risk) (80) + 0.15 * patch (100) + 0.15 * evidence (0) + 0.10 * (100 - surface) (70)
        # posture = 28 + 0 + 15 + 0 + 7 = 50.0
        posture_data = calculate_security_posture(self.session, assessment.id)
        self.assertEqual(posture_data["posture_score"], 50.0)

    def test_configuration_drift_detection(self):
        """Test configuration drift engine alerts when security controls degrade."""
        device = self.session.query(Device).first()
        
        # 1. First completed assessment (All controls pass)
        a1 = Assessment(device_id=device.id, status="Completed", compliance_percentage=100.0)
        self.session.add(a1)
        self.session.commit()
        
        c1 = SecurityControl(control_id="UTSCF-DR-01", domain="Test", name="D1", severity="CRITICAL", control_weight=4.0, validation_type="MANUAL")
        self.session.add(c1)
        self.session.commit()
        
        f1 = Finding(assessment_id=a1.id, control_id=c1.id, status="PASS")
        self.session.add(f1)
        self.session.commit()
        
        # 2. Second assessment (Control degrades to FAIL)
        a2 = Assessment(device_id=device.id, status="In Progress")
        self.session.add(a2)
        self.session.commit()
        
        f2 = Finding(assessment_id=a2.id, control_id=c1.id, status="FAIL")
        self.session.add(f2)
        self.session.commit()
        
        # Run drift detection
        drifts = detect_configuration_drift(self.session, device.id, a2.id)
        
        # Assert drift record is generated
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0].control_id, "UTSCF-DR-01")
        self.assertEqual(drifts[0].old_value, "PASS")
        self.assertEqual(drifts[0].new_value, "FAIL")
        
        # Assert notification was created
        notif = self.session.query(Notification).first()
        self.assertIsNotNone(notif)
        self.assertEqual(notif.type, "DRIFT")
        self.assertIn("degraded from PASS to FAIL", notif.message)

    def test_report_generation(self):
        """Test CSV, Excel TSV, Risk Register, and Remediation report generation."""
        device = self.session.query(Device).first()
        assessment = Assessment(
            device_id=device.id,
            status="In Progress",
            compliance_percentage=80.0,
            risk_score=15.0,
            maturity_level=3
        )
        self.session.add(assessment)
        self.session.commit()
        
        c1 = SecurityControl(control_id="UTSCF-REP-01", domain="Test", name="C1", severity="CRITICAL", control_weight=4.0, validation_type="MANUAL")
        self.session.add(c1)
        self.session.commit()
        
        finding = Finding(assessment_id=assessment.id, control_id=c1.id, status="FAIL", comments="Failed report test")
        self.session.add(finding)
        self.session.commit()
        
        # Import report functions
        from reports import generate_csv_report, generate_html_report, generate_risk_register_csv, generate_remediation_plan_json
        
        csv_data = generate_csv_report(self.session, assessment.id)
        self.assertIn("UTSGRCP ENTERPRISE COMPLIANCE AUDIT REPORT", csv_data)
        self.assertIn("UTSCF-REP-01", csv_data)
        
        html_data = generate_html_report(self.session, assessment.id)
        self.assertIn("UTSGRCP COMPLIANCE AUDIT REPORT", html_data)
        
        org = self.session.query(Organization).first()
        rr_data = generate_risk_register_csv(self.session, org.id)
        self.assertIn("UTSGRCP ENTERPRISE SYSTEM RISK REGISTER", rr_data)
        
        remediation = generate_remediation_plan_json(self.session, assessment.id)
        self.assertEqual(remediation["device_name"], device.name)
        self.assertEqual(len(remediation["remediation_actions"]), 1)

if __name__ == "__main__":
    unittest.main()
