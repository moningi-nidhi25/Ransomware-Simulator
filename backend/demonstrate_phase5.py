"""Demonstration script for Phase 5: Configurable Detection Thresholds.

This script demonstrates:
1. Running a synthetic normal simulation.
2. Running a baseline suspicious simulation under default thresholds.
3. Lowering the modification threshold and saving via PUT /api/settings.
4. Running the suspicious simulation again to demonstrate elevated detection,
   increased risk score, and newly triggered detection reasons.
5. Restoring original settings.

All simulations use synthetic in-memory events; no user files are touched.
"""
import sys
from fastapi.testclient import TestClient
from main import app

def run_demonstration():
    client = TestClient(app)

    print("=" * 70)
    print(" RansomShield - Phase 5 Configurable Detection Demonstration")
    print("=" * 70)

    # Fetch initial settings
    res = client.get("/api/settings")
    if res.status_code != 200:
        print(f"[-] Failed to fetch settings: {res.text}")
        sys.exit(1)
    original_settings = res.json()
    print(f"\n[+] Original Settings: {original_settings}")

    # Step 1: Run normal simulation
    print("\n--- STEP 1: Run Normal Simulation ---")
    res_normal = client.post("/api/simulate/normal")
    normal_data = res_normal.json()
    print(f"    Scenario:        {normal_data['scenario']}")
    print(f"    Risk Score:      {normal_data['risk_score']}/100")
    print(f"    Severity:        {normal_data['severity']}")
    print(f"    Reasons:         {normal_data['reasons']}")
    print(f"    Message:         {normal_data['message']}")

    # Step 2: Run baseline suspicious simulation under original settings
    print("\n--- STEP 2: Run Baseline Suspicious Simulation (Default Thresholds) ---")
    res_susp_base = client.post("/api/simulate/suspicious")
    susp_base_data = res_susp_base.json()
    print(f"    Modification Threshold: {original_settings['modification_threshold']}")
    print(f"    Scenario:               {susp_base_data['scenario']}")
    print(f"    Risk Score:             {susp_base_data['risk_score']}/100")
    print(f"    Severity:               {susp_base_data['severity']}")
    print(f"    Triggered Reasons:      {susp_base_data['reasons']}")
    has_mod_reason_before = "High modification rate" in susp_base_data["reasons"]
    print(f"    'High modification rate' triggered: {has_mod_reason_before}")

    # Step 3: Lower modification threshold and save
    new_settings = dict(original_settings)
    new_settings["modification_threshold"] = 10
    print(f"\n--- STEP 3: Lower Modification Threshold ({original_settings['modification_threshold']} -> {new_settings['modification_threshold']}) ---")
    res_put = client.put("/api/settings", json=new_settings)
    if res_put.status_code != 200:
        print(f"[-] Failed to update settings: {res_put.text}")
        sys.exit(1)
    updated_settings = res_put.json()
    print(f"[+] Settings successfully updated: {updated_settings}")

    # Step 4: Run suspicious simulation again with lower threshold
    print("\n--- STEP 4: Run Suspicious Simulation Again (With Lower Threshold) ---")
    res_susp_after = client.post("/api/simulate/suspicious")
    susp_after_data = res_susp_after.json()
    print(f"    Modification Threshold: {updated_settings['modification_threshold']}")
    print(f"    Scenario:               {susp_after_data['scenario']}")
    print(f"    Risk Score:             {susp_after_data['risk_score']}/100")
    print(f"    Severity:               {susp_after_data['severity']}")
    print(f"    Triggered Reasons:      {susp_after_data['reasons']}")
    has_mod_reason_after = "High modification rate" in susp_after_data["reasons"]
    print(f"    'High modification rate' triggered: {has_mod_reason_after}")

    # Step 5: Restore original settings
    print(f"\n--- STEP 5: Restore Original Settings ---")
    res_restore = client.put("/api/settings", json=original_settings)
    restored_settings = res_restore.json()
    print(f"[+] Settings restored to: {restored_settings}")

    # Summary
    print("\n" + "=" * 70)
    print(" DEMONSTRATION SUMMARY")
    print("=" * 70)
    print(f" Normal Simulation:       Risk={normal_data['risk_score']} | Severity={normal_data['severity']} | Reasons={normal_data['reasons']}")
    print(f" Baseline (Threshold={original_settings['modification_threshold']}):  Risk={susp_base_data['risk_score']} | Severity={susp_base_data['severity']} | Mod Reason={has_mod_reason_before}")
    print(f" Tuned    (Threshold={updated_settings['modification_threshold']}):  Risk={susp_after_data['risk_score']} | Severity={susp_after_data['severity']} | Mod Reason={has_mod_reason_after}")
    print(f" Settings Restored:       {restored_settings == original_settings}")
    print("=" * 70)

if __name__ == "__main__":
    run_demonstration()
