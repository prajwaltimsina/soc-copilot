# soc-copilot
Your AI wingman for network security. Analyzing packet captures to recommend precision defense strategies.

```markdown
# 🛡️ AI-Powered SOC Analyst & Virtual Packet Broker

### A full-stack security telemetry pipeline that captures, analyzes, and remediates network threats using Generative AI.

## 📖 Overview

This project builds a fully functional **Security Operations Center (SOC) Pipeline** from scratch. It simulates an enterprise "Security Fabric" architecture to provide deep network visibility and automates incident response using a Large Language Model (LLM).

Instead of relying on static firewall rules, this system uses **Google Gemini** to analyze threat patterns in real-time and generate context-aware defense strategies for **Hybrid Cloud environments** (Windows & Linux).

## 🏗️ Architecture

The system mimics a standard **Three-Tier Security Architecture**:

1. The Tap (Virtual Switch): Mirrors traffic from a victim VM to the monitoring engine.
2. The Broker (Ingestion Layer): Filters noise, detects L4/L7 anomalies, and triggers high-fidelity PCAP recording.
3. The Vault (Storage Layer): Preserves forensic evidence for analysis on disk.
4. The Brain (Intelligence Layer): An AI agent that analyzes the PCAP metadata and determines the remediation strategy.
5. The Dashboard (Visualization): A live Flask-based UI for visualizing the Kill Chain.

### Data Flow Diagram

+-----------------+       +------------------+       +----------------------+
|   Attacker VM   | ----> |  Virtual Switch  | ----> |   Packet Broker      |
|  (Kali/Manual)  |       |   (Mirror Port)  |       |   (monitor_lab.py)   |
+-----------------+       +------------------+       +----------+-----------+
                                                                |
                                                                v
                                                     +----------+-----------+
                                                     |      Evidence Vault  |
                                                     |     (evidence_data/) |
                                                     +----------+-----------+
                                                                |
                                                                v
                                                     +----------+-----------+
                                                     |      AI Engine       |
      +----------------+                             |     (ai_logic.py)    |
      |   Gemini API   | <-------------------------> |                      |
      +----------------+                             +----------+-----------+
                                                                |
                                                                v
                                                     +----------+-----------+
                                                     |    Web Dashboard     |
                                                     |    (dashboard.py)    |
                                                     +----------------------+

```

## 🚀 Key Features

* Virtual Packet Broker: Custom Scapy engine designed to filter high-volume enterprise noise (e.g., Windows Delivery Optimization, mDNS, SSDP) to focus on high-fidelity threat detection.
* Deep Packet Inspection (DPI): Detects cleartext credential leaks inside HTTP payloads.
* Forensic Capture: Automatically saves individual `.pcap` files for every triggered alert.
* GenAI Intelligence: Uses Google Gemini to differentiate between Network Attacks and provide dynamic remediation.
* Hybrid Defense: AI generates both Linux and Windows defense commands.
* Live Dashboard: A real-time "Red/Green" status monitor built with Flask.

## 🛠️ Tech Stack

* Language: Python 3.10+
* Network Analysis: Scapy
* AI/LLM: Google Generative AI (Gemini 1.5)
* Web Framework: Flask
* Forensics: Wireshark (for validation)

## 📂 Project Structure

```bash
├── monitor_lab.py      # The Broker: Sniffs, Filters, and Captures Packets
├── ai_logic.py         # The Brain: Sends Alerts to Gemini & processes logic
├── dashboard.py        # The UI: Renders the Live Web Dashboard
├── tcpdump.txt         # Raw baseline traffic logs for validation
├── latest_alert.json   # Shared state file for data persistence
├── evidence_data/      # Directory where forensic .pcap files are stored
└── screenshots/        # Images used in the README (Dashboard & Wireshark)

```

## ⚙️ Installation & Setup

1. **Clone the Repository**
```bash
git clone https://github.com/<your-username>/soc-copilot.git
cd soc-copilot

```

2. **Create a Virtual Environment**
```bash
python3 -m venv venv
source venv/bin/activate

```

3. **Install Dependencies**
```bash
pip install scapy flask google-generativeai

```

4. **Configure API Key**
* Get a free API key from [Google AI Studio](https://aistudio.google.com/).
* Open `ai_logic.py` and replace `API_KEY` with your actual key.

## ⚡ Usage Guide

This system requires running three separate terminal instances to simulate the microservices architecture.

**Terminal 1: The Packet Broker (Needs Sudo)**
*Listens for attacks and saves PCAPs.*

```bash
sudo ./venv/bin/python3 monitor_lab.py

```

**Terminal 2: The AI Engine**
*Monitors the evidence folder and consults Gemini.*

```bash
./venv/bin/python3 ai_logic.py

```

**Terminal 3: The Dashboard**
*Hosts the live web interface.*

```bash
./venv/bin/python3 dashboard.py

```

**Simulate an Attack:**
You can test the detection engine with various attack vectors from a separate terminal or VM (e.g., Kali Linux):

```bash
# 1. SSH Brute Force / Access Attempt
ssh root@<TARGET_IP>

# 2. Nmap TCP SYN Scan (Port Scanning)
nmap -sS -p 80,443,22 <TARGET_IP>

# 3. UDP Flood / DoS Simulation (using Hping3)
sudo hping3 --udp --flood <TARGET_IP>

```


### 🧩 Customizing Detection Logic (Extending the Broker)

The `monitor_lab.py` script acts as the Packet Broker. It uses a series of `if/elif` statements in the `packet_callback` function to filter traffic and assign "Attack Labels" before saving the evidence.

To capture new attack types (like UDP Floods or specific Malware signatures), you simply add a new Trigger block in `monitor_lab.py`.

**Example: Adding UDP Flood Detection**
Paste this code block into `monitor_lab.py` before the "Catch-All" Port Scan trigger:

```python
        # TRIGGER: UDP Flood / DoS
        if pkt.haslayer(UDP):
            print(f"[!] TRIGGER: High-Volume UDP Traffic from {src_ip} -> CAPTURING EVIDENCE")
            filename = f"{PCAP_PATH}attack_udpflood_{src_ip}.pcap"
            wrpcap(filename, pkt, append=True)
            return

```

## 📸 Screenshot

### The Live Dashboard (Under Attack)
The dashboard reacting instantly to an SSH attack with AI-suggested firewall rules.

<img width="2880" height="1115" alt="dashboard" src="https://github.com/user-attachments/assets/a293e6ed-18a9-428a-b727-c0f2ba95df49" />

## 🔗 Related Work

If you enjoyed building a custom SOC pipeline from scratch, check out my deep dive into enterprise-grade threat hunting using **Wazuh SIEM**:

👉 **[Leveraging Wazuh & AI for Threat Hunting: My End-to-End Lab Walkthrough](https://prajwaltimsina.medium.com/%EF%B8%8F-leveraging-wazuh-ai-for-threat-hunting-my-end-to-end-lab-walkthrough-6de44a39b67a)**

*While this project focuses on **building** the tools (Python/Scapy), the Wazuh lab focuses on **deploying** industry-standard EDR/SIEM solutions.*

## 🔮 Future Scope

* **Automated Blocking:** Integrate with `fail2ban` or `iptables` to automatically apply the AI's suggestions.
* **Cloud Integration:** Send logs to AWS CloudWatch or Azure Sentinel.
* **Reporting:** Generate a PDF incident report at the end of every day.

## ⚠️ Disclaimer

This project is for **educational purposes only**. It is designed to be run in a controlled, isolated lab environment. Do not use this tool on networks you do not own or have permission to test.
