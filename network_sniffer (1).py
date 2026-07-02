"""
TASK 1: Basic Network Sniffer
CodeAlpha Cybersecurity Internship
Author: [Your Name]
Description: Captures and analyzes network packets using Scapy
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
from datetime import datetime
import argparse

# ─────────────────────────────────────────────
# Packet Handler
# ─────────────────────────────────────────────
def packet_handler(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(IP):
        src_ip  = packet[IP].src
        dst_ip  = packet[IP].dst
        proto   = packet[IP].proto

        print(f"\n{'='*60}")
        print(f"  [⏱ {timestamp}]  New Packet Captured")
        print(f"{'='*60}")
        print(f"  Source IP      : {src_ip}")
        print(f"  Destination IP : {dst_ip}")

        # TCP
        if packet.haslayer(TCP):
            print(f"  Protocol       : TCP")
            print(f"  Src Port       : {packet[TCP].sport}")
            print(f"  Dst Port       : {packet[TCP].dport}")
            print(f"  TCP Flags      : {packet[TCP].flags}")

        # UDP
        elif packet.haslayer(UDP):
            print(f"  Protocol       : UDP")
            print(f"  Src Port       : {packet[UDP].sport}")
            print(f"  Dst Port       : {packet[UDP].dport}")

        # ICMP
        elif packet.haslayer(ICMP):
            print(f"  Protocol       : ICMP")
            print(f"  ICMP Type      : {packet[ICMP].type}")

        else:
            print(f"  Protocol       : Other (proto={proto})")

        # Payload
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                decoded = raw_data.decode('utf-8', errors='replace')[:100]
                print(f"  Payload        : {decoded}")
            except Exception:
                print(f"  Payload (hex)  : {raw_data.hex()[:60]}")

    # Non-IP (ARP etc.)
    elif packet.haslayer(Ether):
        print(f"\n[{timestamp}] Non-IP Ethernet Frame | "
              f"Src MAC: {packet[Ether].src} → Dst MAC: {packet[Ether].dst}")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer — CodeAlpha")
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=20,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter string (e.g., 'tcp port 80')")
    args = parser.parse_args()

    print("=" * 60)
    print("   🔍 Basic Network Sniffer — CodeAlpha Internship")
    print("=" * 60)
    print(f"  Interface : {args.interface or 'Default'}")
    print(f"  Count     : {args.count or 'Unlimited'}")
    print(f"  Filter    : '{args.filter}' " if args.filter else "  Filter    : None")
    print("  Press Ctrl+C to stop.\n")

    sniff(
        iface=args.interface,
        prn=packet_handler,
        count=args.count,
        filter=args.filter,
        store=False
    )

    print("\n✅ Sniffing complete.")

if __name__ == "__main__":
    main()
