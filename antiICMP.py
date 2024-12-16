from scapy.all import sniff, TCP, IP
import os

def detect_syn_scan(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        print(f"SYN scan detected from {packet[IP].src}")
        # Correct route command
        os.system(rf"C:\Windows\System32\ROUTE.EXE add {packet[IP].src} mask 255.255.255.255 0.0.0.0")

sniff(filter="tcp", prn=detect_syn_scan)
