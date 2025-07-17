from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    print("\n--- Packet Captured ---")
    
    # Check if IP layer exists
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
    
    # TCP or UDP
    if packet.haslayer(TCP):
        print("Protocol: TCP")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print("Protocol: UDP")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
    
    # Print Raw Payload if present
    if packet.haslayer(Raw):
        print(f"Payload: {packet[Raw].load}")

# Sniff packets on a specific interface (e.g., 'eth0' or 'Wi-Fi' on Windows)
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(filter="ip", prn=process_packet, store=False)
