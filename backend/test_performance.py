import time
import datetime
import statistics
from sqlalchemy.orm import Session
from database import engine, Base
from models import Organization, Site, Building, DeviceGroup, Device, SecurityControl, Assessment, Finding
from seed_data import seed_database
from engines import recalculate_assessment_risks, calculate_security_posture

def run_performance_simulation():
    print("=======================================================================")
    print("          UTSGRCP ENTERPRISE PERFORMANCE SCALABILITY SIMULATOR")
    print("=======================================================================")
    
    # Setup fresh memory DB for simulation run to avoid bloating local files
    print("\n[1/4] Initializing memory database and seeding UTSCF controls...")
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    
    # Ensure database is seeded
    if db.query(SecurityControl).count() == 0:
        seed_database(db)
        
    # Get references
    group = db.query(DeviceGroup).first()
    if not group:
        # Create default tenant hierarchy if missing
        org = Organization(name="Sim Corp")
        db.add(org); db.commit()
        site = Site(name="Sim Site", organization_id=org.id)
        db.add(site); db.commit()
        building = Building(name="Sim Building", site_id=site.id)
        db.add(building); db.commit()
        group = DeviceGroup(name="Sim Group", building_id=building.id)
        db.add(group); db.commit()
        
    controls = db.query(SecurityControl).all()
    
    # 500 Device Generation
    NUM_DEVICES = 500
    print(f"\n[2/4] Generating {NUM_DEVICES} virtual Tizen devices & active assessments...")
    start_gen = time.time()
    
    devices = []
    assessments = []
    
    for i in range(NUM_DEVICES):
        dev = Device(
            name=f"Sim-TV-{i:03d}",
            model="QM55R Smart Signage",
            serial_number=f"SIM-SN-{i:05d}",
            firmware_version="T-MS12WWD-1004.2",
            tizen_version="6.5",
            mac_address=f"00:11:22:33:44:{i:02x}"[:17],
            ip_address=f"10.0.1.{i % 255}",
            device_group_id=group.id,
            business_criticality="HIGH" if i % 10 == 0 else "MEDIUM"
        )
        db.add(dev)
        devices.append(dev)
        
    db.commit()
    
    # Create assessments and findings for all 500
    for dev in devices:
        ass = Assessment(
            device_id=dev.id,
            status="In Progress",
            compliance_percentage=0.0,
            risk_score=100.0,
            posture_score=0.0,
            attack_surface_score=0.0,
            maturity_level=1,
            created_at=datetime.datetime.utcnow(),
            updated_at=datetime.datetime.utcnow()
        )
        db.add(ass)
        assessments.append(ass)
    db.commit()
    
    # Add findings bulk
    print("      Staging rule findings for database write...")
    for ass in assessments:
        for c in controls:
            f = Finding(
                assessment_id=ass.id,
                control_id=c.id,
                status="PASS" if (ass.id + c.id) % 8 != 0 else "FAIL", # semi-random compliance
                comments="Performance simulation scan run.",
                risk_accepted=False
            )
            db.add(f)
    db.commit()
    
    gen_time = time.time() - start_gen
    print(f"      Created {NUM_DEVICES} devices & {NUM_DEVICES * len(controls)} findings in {gen_time:.2f} seconds.")
    
    # Run evaluation sweep
    print(f"\n[3/4] Running concurrent compliance calculations on {NUM_DEVICES} devices...")
    latencies = []
    start_eval = time.time()
    
    for idx, ass in enumerate(assessments):
        t0 = time.time()
        # Execute engines logic
        recalculate_assessment_risks(db, ass.id)
        calculate_security_posture(db, ass.id)
        latency = (time.time() - t0) * 1000 # ms
        latencies.append(latency)
        
        if (idx + 1) % 100 == 0:
            print(f"      Processed {idx + 1} / {NUM_DEVICES} assessments...")
            
    eval_time = time.time() - start_eval
    throughput = NUM_DEVICES / eval_time
    
    # Stats metrics
    avg_lat = statistics.mean(latencies)
    med_lat = statistics.median(latencies)
    std_lat = statistics.stdev(latencies)
    max_lat = max(latencies)
    min_lat = min(latencies)
    
    print(f"\n[4/4] Simulation Complete!")
    print("-----------------------------------------------------------------------")
    print(f"Total Execution Time:        {eval_time:.3f} seconds")
    print(f"Throughput Rate:             {throughput:.2f} assessments / second")
    print(f"Average Evaluation Latency:  {avg_lat:.2f} ms")
    print(f"Median Evaluation Latency:   {med_lat:.2f} ms")
    print(f"Standard Deviation:          {std_lat:.2f} ms")
    print(f"Max Latency:                 {max_lat:.2f} ms")
    print(f"Min Latency:                 {min_lat:.2f} ms")
    print("-----------------------------------------------------------------------")
    
    # Clean up simulation records
    print("Cleaning up simulated device records...")
    for ass in assessments:
        db.query(Finding).filter(Finding.assessment_id == ass.id).delete()
    for ass in assessments:
        db.query(Assessment).filter(Assessment.id == ass.id).delete()
    for dev in devices:
        db.query(Device).filter(Device.id == dev.id).delete()
    db.commit()
    db.close()
    print("Done.")

if __name__ == "__main__":
    run_performance_simulation()
