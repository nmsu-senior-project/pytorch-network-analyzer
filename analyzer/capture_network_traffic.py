import os
from datetime import datetime
from venv import logger

import mysql.connector
from scapy.all import *
from scapy.arch.windows import get_windows_if_list

# Constants
PACKET_LIMIT = 1000
TIMEOUT = 600 # 10 minutes
OUTPUT_DIR = "pcap_files"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# List to store captured packets
captured_packets = []


def read_credentials(filename):
    credentials = {}
    with open(filename, 'r') as file:
        for line in file:
            key, value = line.strip().split(':')
            credentials[key.strip()] = value.strip()
    return credentials

# Usage
credentials = read_credentials('credentials.txt')
db_user = credentials.get('db_user')
db_pass = credentials.get('db_pass')


def capture_traffic(interface_name, captured_packets):
    """Captures traffic on the specified interface and stores packets in a list."""
    print(f"Starting capture on interface: {interface_name}")
    packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")
    packet_count = 0

    try:
        # Define a callback function to store each packet in the captured_packets list
        def store_packet(pkt):
            nonlocal packet_count

            packet_count += 1
            captured_packets.append(pkt)
            print(captured_packets[-1])

            if packet_count >= PACKET_LIMIT:
                # If the packet count reaches or exceeds the limit, stop packet capture
                return False  # Returning False stops the packet capture

        # Start packet capture, using the store_packet callback to store each packet
        sniff(iface=interface_name, prn=store_packet, timeout=TIMEOUT, stop_filter=lambda _: packet_count >= PACKET_LIMIT)

        packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
        # Write captured packets to a PCAP file
        pcap_filename = os.path.join(OUTPUT_DIR, f"{interface_name}-({packet_time_started})-({packet_time_ended}).pcap")
        wrpcap(pcap_filename, captured_packets)
        print(f"Captured packets written to {pcap_filename}")
        print("Capture completed.")

        subprocess.run(['python', 'scan_network_traffic.py'])
    except Exception as e:
        print(f"Error capturing traffic on {interface_name}: {e}")


def main():
    #connect to database
    try:
        mysqlcon = mysql.connector.connect(user=db_user,
                                    password=db_pass,
                                    host="localhost",
                                    port=3306,
                                    database="localhost")
        mysqlcon.autocommit = True
        print("Connected to database as " + db_user)
    except mysql.connector.Error as err:
        logger.info(err)
        sys.exit()

    """Prompts user for interface selection by name and starts capture."""
    interfaces = get_windows_if_list()
    print("Available interfaces:")
    for interface in interfaces:
        interface_name = interface['name']
        interface_ips = ', '.join(interface['ips'])
        print(f"Name: {interface_name}, IPs: {interface_ips}")

    while True:
        interface_name = input("Enter interface name (or 'q' to quit): ")
        if interface_name.lower() == 'q':
            break
        if any(interface['name'] == interface_name for interface in interfaces):
            capture_traffic(interface_name, captured_packets)
            break  # Exit after capturing on one interface
        else:
            print("Invalid interface name. Please try again.")

if __name__ == "__main__":
    main()