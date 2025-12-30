import time
import os
import json
import warnings

# --- 1. SUPPRESS WARNINGS ---
warnings.simplefilter(action='ignore', category=FutureWarning)

import google.generativeai as genai

# --- CONFIGURATION ---
EVIDENCE_PATH = "./cstor_data/"
DASHBOARD_FILE = "latest_alert.json"
PROCESSED_FILES = set()
RESET_TIMEOUT = 20  # Seconds to wait before auto-clearing the dashboard

# --- 2. API KEY ---
API_KEY = "YOUR-API-KEY-HERE"

genai.configure(api_key=API_KEY)

# --- 3. AUTO-DETECT MODEL ---
print("[-] Checking available AI Models...")
model_name = "gemini-pro"
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            if 'flash' in m.name:
                model_name = m.name
                break
            elif '1.5' in m.name:
                model_name = m.name
except:
    pass

print(f"[+] Using AI Model: {model_name}")
model = genai.GenerativeModel(model_name)

print("--- cClear INTELLIGENCE ENGINE (Backend) ACTIVE ---")
print("[-] Waiting for evidence from cStor...")

# Track state for auto-reset
last_alert_time = 0
is_active_alert = False

def reset_dashboard():
    """Resets the dashboard to System Secure"""
    safe_data = {
        "severity": "SAFE",
        "summary": "System Normal",
        "action": "Monitoring Network Telemetry...",
        "ip": "N/A"
    }
    with open(DASHBOARD_FILE, "w") as f:
        json.dump(safe_data, f)
    print("    [*] Alert expired. Dashboard reset to SAFE.")

def analyze_threat_with_gemini(attack_type, ip, file_path):
    global last_alert_time, is_active_alert
    
    print(f"\n[+] NEW EVIDENCE: {attack_type} from {ip}")
    print(f"    [...] Sending metadata to Gemini AI...")
    
    # --- UPDATED PROMPT: DYNAMIC RESPONSE ---
    prompt = (
        f"You are a Senior SOC Analyst handling a security incident.\n"
        f"A threat has been detected.\n"
        f"Attack Type: {attack_type}\n"
        f"Source IP/Context: {ip}\n\n"
        
        f"Analyze the specific nature of this attack and determine the SINGLE best technical remediation step.\n"
        f"- If it is a Network Attack (Scan, DDoS), provide a Firewall Block command (iptables or PowerShell).\n"
        f"- If it is an Identity Attack (Credential Leak, Brute Force), provide a User Account Lockout command or Password Reset syntax.\n"
        f"- If it is a Web Attack, provide a WAF block rule.\n\n"
        
        f"Provide a JSON response with:\n"
        f"1. 'severity': (CRITICAL, HIGH, or MEDIUM)\n"
        f"2. 'summary': A short, urgent description (max 10 words).\n"
        f"3. 'action': The specific command line instruction to execute the fix you decided on.\n"
        f"Do not include markdown formatting, just raw JSON."
    )

    try:
        response = model.generate_content(prompt)
        clean_text = response.text.replace("```json", "").replace("```", "").strip()
        data = json.loads(clean_text)
        
        data["timestamp"] = time.strftime("%H:%M:%S")
        data["ip"] = ip
        data["type"] = attack_type

        # Update Dashboard
        with open(DASHBOARD_FILE, "w") as f:
            json.dump(data, f)
            
        print(f"    [OK] ALERT SENT TO DASHBOARD: {data['summary']}")
        print(f"    [>] Dynamic Action: {data['action']}")
        
        # Update timer
        last_alert_time = time.time()
        is_active_alert = True
        
    except Exception as e:
        print(f"[!] AI ERROR: {e}")

# --- MAIN LOOP ---
reset_dashboard()

while True:
    try:
        files = os.listdir(EVIDENCE_PATH)
        for filename in files:
            if filename.endswith(".pcap") and filename not in PROCESSED_FILES:
                try:
                    parts = filename.split("_")
                    attack_type = parts[1].upper()
                    ip = parts[2].replace(".pcap", "")
                    
                    analyze_threat_with_gemini(attack_type, ip, filename)
                    PROCESSED_FILES.add(filename)
                except:
                    pass
        
        # Auto-Reset Logic
        if is_active_alert and (time.time() - last_alert_time > RESET_TIMEOUT):
            reset_dashboard()
            is_active_alert = False

    except Exception as e:
        pass
    
    time.sleep(2)
