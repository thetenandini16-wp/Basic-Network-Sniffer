from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from datetime import datetime

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Protocol identify karna
        if TCP in packet:
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"[{datetime.now().strftime('%H:%M:%S')}] TCP  | {src_ip}:{sport} -> {dst_ip}:{dport}")
        elif UDP in packet:
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"[{datetime.now().strftime('%H:%M:%S')}] UDP  | {src_ip}:{sport} -> {dst_ip}:{dport}")
        elif ICMP in packet:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ICMP | {src_ip} -> {dst_ip}")
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Other proto ({proto}) | {src_ip} -> {dst_ip}")

        # Payload dikhana (agar present hai)
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            print(f"    Payload (first 50 bytes): {payload[:50]}")

def start_sniffer(count=20):
    print("Starting network sniffer... (Press Ctrl+C to stop)\n")
    sniff(prn=analyze_packet, count=count, store=False, iface=get_if_list()[0])

if __name__ == "__main__":
    start_sniffer(count=30)  # 30 packets capture karega