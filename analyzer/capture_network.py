import re
import os, time

from datetime import datetime

import mysql.connector as mysql
from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP, Raw
from scapy.layers.inet6 import IPv6

from setup_network import INTERFACE_NAME, DB_CONFIG, DATABASE_NAME, TABLE_NAME

# Constants
PACKET_LIMIT = 1000
TIMEOUT = 30 #seconds
OUTPUT_DIR = "pcap_files"

os.makedirs(OUTPUT_DIR, exist_ok=True)

pcap_filename = None
captured_packets = []


def connect_to_db(db_config):
    connection = mysql.connect(**db_config)
    cursor = connection.cursor()

    return cursor, connection


def determine_protocol(packet):
    """Determines the protocol of the packet based on the layers present."""
    IGNORED_KEYWORDS = ['Padding', 'Raw', 'Router Alert']

    def sanitize_string(content):
        return re.sub(r'[^a-zA-Z0-9\s]', '', content).strip()

    #Mitigates timestamp error issues
    try:
        packet_info = packet.show(dump=True)
    except OSError as e:
        if e.errno == 22:
            # Handle invalid timestamp error
            print(f"Invalid timestamp in packet: {packet}")
            return []
        else:
            raise

    pattern = re.compile(r"(##\#[^\n]*###(?:\n {2,}.*)*)")
    matches = pattern.findall(packet_info)
    protocol_array = []

    # Extract and store each protocol section
    for protocol_section in matches[:4]:  # Limit to the first four matches
        for line in protocol_section.splitlines():
            if line.strip().startswith("###["):
                # Extract protocol name from ###[ ... ]###
                protocol_name = line.strip()[4:-3].strip()
                protocol_name = sanitize_string(protocol_name)
                if protocol_name not in IGNORED_KEYWORDS:
                    protocol_array.append(protocol_name)
            else:
                sanitized_line = sanitize_string(line.strip())
                if sanitized_line not in IGNORED_KEYWORDS:
                    protocol_array.append(sanitized_line)

    return protocol_array


def packet_to_db(pcap_filename):
    """Inserts packet data into the database."""

    # Connect to the database
    cursor, connection = connect_to_db(DB_CONFIG)

    packets = rdpcap(pcap_filename)

    for packet in packets:

        protocol_array = determine_protocol(packet)

        timestamp = datetime.fromtimestamp(float(packet.time))
        source_mac = packet[Ether].src if Ether in packet else None
        destination_mac = packet[Ether].dst if Ether in packet else None
        source_ip = source_ip = packet[IP].src if IP in packet else (packet[IPv6].src if IPv6 in packet else None)
        destination_ip = packet[IP].dst if IP in packet else None
        source_port = packet.sport if TCP in packet else packet[UDP].sport if UDP in packet else None
        destination_port = packet.dport if TCP in packet else packet[UDP].dport if UDP in packet else None
        ethernet_type = str(protocol_array[0]).strip() if len(protocol_array) >= 1 else None
        network_protocol = str(protocol_array[1]).strip() if len(protocol_array) >= 2 else None
        transport_protocol = str(protocol_array[2]).strip() if len(protocol_array) >= 3 else None
        application_protocol = str(protocol_array[3]).strip() if len(protocol_array) >= 4 else None

        # Protocol and payload
        payload = bytes(packet[Raw].load) if Raw in packet else None

        # Update database schema (if needed)
        insert_query = (
            f"INSERT INTO {TABLE_NAME} (timestamp, source_mac, destination_mac, source_ip, destination_ip, "
            f"source_port, destination_port, ethernet_type, network_protocol, transport_protocol, "
            f"application_protocol, payload) "
            f"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        )

        try:
            # Execute the insertion query
            cursor.execute(f"USE {DATABASE_NAME}")
            cursor.execute(insert_query, (timestamp, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port, ethernet_type, network_protocol, transport_protocol, application_protocol, payload))
            connection.commit()
            # print("Packet successfully inserted into database.")
        except mysql.Error as err:
            print(f"Error inserting packet into database DETAILS: {err}")

    # Close the database connection
    cursor.close()


def capture_traffic():
    """Captures traffic on the specified interface and stores packets in a list."""
    packet_count = 0
    start_time = time.time()
    packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")

    try:
        # # Define a callback function to store each packet in the captured_packets list
        def store_packet(pkt):
            nonlocal packet_count
            packet_count += 1
            captured_packets.append(pkt)


        #scan the network
        sniff(iface=INTERFACE_NAME, prn=store_packet, timeout=TIMEOUT, stop_filter=lambda _: packet_count == PACKET_LIMIT)
        
        packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
        print(f"Capture in {time.time() - start_time} seconds.")
        print(f"Total packet count: {str(packet_count)} \n")

        # Write captured packets to a PCAP file
        # FYI: Comment these three lines if PCAP creation is not needed.
        pcap_filename = os.path.join(OUTPUT_DIR, f"{INTERFACE_NAME}-({packet_time_started})-({packet_time_ended}).pcap")
        wrpcap(pcap_filename, captured_packets)

    except Exception as e:
        print(f"Error capturing traffic on {INTERFACE_NAME}: {e}")
    
    return pcap_filename

# Main function
pcap_filename = capture_traffic()
packet_to_db(pcap_filename)