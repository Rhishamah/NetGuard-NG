from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv, time
import os

OUTPUT = "data/traffic.csv"

def process_packet(writer, packet):
    if IP not in packet:
        return
    src, dst = packet[IP].src, packet[IP].dst
    if TCP in packet:
        proto, port = "TCP", packet[TCP].dport
        flags = str(packet[TCP].flags)
    elif UDP in packet:
        proto, port = "UDP", packet[UDP].dport
        flags = ""
    elif ICMP in packet:
        proto, port = "ICMP", None
        flags = ""
    else:
        return
    writer.writerow([src, dst, proto, port, flags, len(packet), packet.time])
# to build up bigger datasets across multiple runs switch w to a(append mode ) so every run does not wipe the previous capture  & also raise count to get a real windows worth of data to test
def main():
    file_exists = os.path.exists(OUTPUT) and os.path.getsize(OUTPUT) > 0
    with open(OUTPUT, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["src_ip", "dst_ip", "protocol", "port", "flags", "size", "timestamp"])
        sniff(iface="wlp2s0", prn=lambda pkt: process_packet(writer, pkt),
              store=False, count=40)

if __name__ == "__main__":
    main()