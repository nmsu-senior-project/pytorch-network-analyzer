from scapy.all import sniff, wrpcap, get_if_list

# List to store captured packets
captured_packets = []

# Define a packet handler function
def packet_handler(packet):
    captured_packets.append(packet)

# Display available network interfaces
print("Available interfaces:")
for iface in get_if_list():
    print(iface)

# Specify the network interface for capturing packets
interface = input("What interface do you want to use?: ")  # Replace with the actual interface name

# Capture packets
print(f"Starting packet capture on {interface}...")
sniff(iface=interface, prn=packet_handler, timeout=10)


# Save the captured packets to a pcap file
output_file = 'captured_traffic.pcap'
wrpcap(output_file, captured_packets)
print(f"Packet capture complete. Saved to {output_file}.")