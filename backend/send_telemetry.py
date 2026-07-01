import requests
import json
import sys

# Target GRC Server URL
API_URL = "http://127.0.0.1:8000"

def simulate_tizen_agent():
    print("==========================================================")
    # 1. Authenticate with GRC Server to obtain JWT Token
    print("[1/3] Authenticating with GRC Server...")
    login_data = {
        "username": "superadmin",
        "password": "password123"
    }
    
    try:
        response = requests.post(f"{API_URL}/api/auth/login", data=login_data)
        if response.status_code != 200:
            print("Error: Authentication failed. Make sure your FastAPI server is running.")
            return
            
        token = response.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}
        print("      Authentication Successful! JWT token obtained.")
        
        # 2. Fetch active assessments
        print("\n[2/3] Fetching active assessments...")
        assessments_resp = requests.get(f"{API_URL}/api/assessments", headers=headers)
        assessments = assessments_resp.json()
        
        if not assessments:
            print("Error: No active assessments found in GRC database.")
            return
            
        # Target the first assessment
        target_ass = assessments[0]
        ass_id = target_ass["id"]
        dev_name = target_ass["device"]["name"]
        print(f"      Targeting Assessment ID: {ass_id} for device: {dev_name}")
        
        # 3. Simulate and Send Telemetry Scan Payload
        print("\n[3/3] Sending simulated Tizen device telemetry scan payload...")
        
        # Trigger automated scan via the backend engine
        scan_resp = requests.post(f"{API_URL}/api/assessments/{ass_id}/scan", headers=headers)
        
        if scan_resp.status_code == 200:
            metrics = scan_resp.json()
            print("----------------------------------------------------------")
            print("✔ Telemetry Ingested & Posture Recalculated Successfully!")
            print(f"  New Posture Score:     {metrics.get('posture_score'):.2f} / 100")
            print(f"  New Compliance Rate:   {metrics.get('compliance_percentage'):.2f}%")
            print(f"  New Residual Risk:     {metrics.get('risk_score'):.2f}")
            print(f"  New Attack Surface:    {metrics.get('attack_surface_score'):.2f}")
            print("----------------------------------------------------------")
            print("Check your browser dashboard - the scores have updated live!")
        else:
            print(f"Error: Telemetry scan ingestion returned code {scan_resp.status_code}")
            
    except Exception as e:
        print(f"Network Connection Error: {e}")

if __name__ == "__main__":
    simulate_tizen_agent()
