import os
from scapy.all import *

# --- CONFIGURATION (The "Broker" Rules) ---
IFACE = "enx90cc245d2254"
PCAP_PATH = "./cstor_data/"
IGNORE_SERVICES = ["_dosvc", "homerig", ".local", "mdns", "224.0.0.251"]

# --- SETUP ---
if not os.path.exists(PCAP_PATH):
    os.makedirs(PCAP_PATH)
    print(f"[*] Created evidence directory: {PCAP_PATH}")

def analyze_packet(pkt):
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        
        # --- LAYER 1: FILTERING (Dropping Noise) ---
        if pkt.haslayer(DNSQR):
            try:
                query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                if any(s in query for s in IGNORE_SERVICES):
                    return 
            except:
                pass 

        # --- LAYER 2: THREAT DETECTION (Specific -> Generic) ---

        # TRIGGER A: Deep Packet Inspection (Check this FIRST)
        # We look inside the payload. If we see a password, we want to know immediately.
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                if "password" in payload.lower() or "user=" in payload.lower() or "admin" in payload.lower():
                    print(f"[!!!] CRITICAL: Cleartext Credential Leak from {src_ip} -> CAPTURING EVIDENCE")
                    filename = f"{PCAP_PATH}alert_credential_leak_{src_ip}.pcap"
                    wrpcap(filename, pkt, append=True)
                    return  # Stop here so we don't log it as a port scan too
            except:
                pass 

        # TRIGGER B: SSH Access (Check this SECOND)
        # Label Port 22 explicitly as "SSH"
        if pkt.haslayer(TCP) and pkt[TCP].dport == 22:
            print(f"[!] TRIGGER: SSH Admin Access Attempt from {src_ip} -> CAPTURING EVIDENCE")
            filename = f"{PCAP_PATH}attack_ssh_{src_ip}.pcap"
            wrpcap(filename, pkt, append=True)
            return

        # TRIGGER C: Port Scan (Check this LAST)
        # This is the "Catch-All" for any other connection attempt
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            print(f"[!] TRIGGER: Port Scan Detected from {src_ip} -> CAPTURING EVIDENCE")
            filename = f"{PCAP_PATH}attack_portscan_{src_ip}.pcap"
            wrpcap(filename, pkt, append=True)
            return

        # TRIGGER D: ICMP Activity
        if pkt.haslayer(ICMP):
            msg_type = "REQUEST" if pkt[ICMP].type == 8 else "REPLY"
            print(f"[*] TRIGGER: ICMP {msg_type} from {src_ip} -> LOGGING TO STORAGE")
            filename = f"{PCAP_PATH}traffic_icmp_{src_ip}.pcap"
            wrpcap(filename, pkt, append=True)

# --- MAIN EXECUTION ---
print("--- cPacket VIRTUAL BROKER ACTIVE ---")
print(f"Listening on: {IFACE}")
print(f"Saving Evidence to: {PCAP_PATH}")
print("-------------------------------------")

sniff(iface=IFACE, prn=analyze_packet, store=0)