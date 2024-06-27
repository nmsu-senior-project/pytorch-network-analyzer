import logging
import re
import os,sys, time, subprocess
from analyze_network import begin_scan

from datetime import datetime

import pandas as pd
import mysql.connector as mysql
from scapy.arch.windows import get_windows_if_list
from scapy.all import sniff, wrpcap, rdpcap, Ether, LLC, IP, TCP, UDP, Raw, ARP, ICMP, DNS, STP
from scapy.contrib.igmp import IGMP
from scapy.layers.http import HTTP
from scapy.layers.inet6 import _ICMPv6 as ICMPv6, IPv6


# Constants
PACKET_LIMIT = 1000
TIMEOUT = 30 #seconds
OUTPUT_DIR = "pcap_files"

os.makedirs(OUTPUT_DIR, exist_ok=True)

protocol_dict = {}
captured_packets = []


def print_divider(length, newline_count):
    print('-' * length + "\n" * newline_count)


def port_to_dict():
    # Define the path to the CSV file
    csv_file_path = 'resources/service-names-port-numbers.csv'

    # Load the CSV file into a DataFrame
    protocol_data = pd.read_csv(csv_file_path)

    global protocol_dict

    # Populate the dictionary with port numbers as keys and a list of service-protocol pairs as values
    for _, row in protocol_data.iterrows():
        application_protocol = row['Service Name']
        port_number = row['Port Number']
        transport_protocol = str(row['Transport Protocol']).lower()  # Convert protocol to lowercase

        # Check for valid data and convert port number to integer
        if pd.notna(application_protocol) and pd.notna(port_number) and pd.notna(str(transport_protocol)):
            try:
                port_number = int(port_number)
                if port_number not in protocol_dict:
                    protocol_dict[port_number] = []
                protocol_dict[port_number].append(f"{application_protocol} ({str(transport_protocol)})")
            except ValueError:
                continue


def capture_traffic(interface_name, db_config):
    """Captures traffic on the specified interface and stores packets in a list."""
    print_divider(80, 1)

    print(f"Starting capture on interface {interface_name}:")
    print_divider(41, 0)
    packet_count = 0

    try:
        # # Define a callback function to store each packet in the captured_packets list
        def store_packet(pkt):
            nonlocal packet_count
            packet_count += 1
            captured_packets.append(pkt)
        #     packet_to_db(pkt, db_config)

        #     if packet_count >= PACKET_LIMIT:
        #         return False  # Returning False stops the packet capture

        # Start packet capture, using the store_packet callback to store each packet
        packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")

        print("Started capture at " + packet_time_started)

        #scan the network
        sniff(iface=interface_name, prn=store_packet, timeout=TIMEOUT, stop_filter=lambda _: packet_count == PACKET_LIMIT)
        
        packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
        print("Ended capture at " + packet_time_ended)
        print(f"Total packet count: {str(packet_count)} \n")

        # Write captured packets to a PCAP file
        # FYI: Comment these three lines if PCAP creation is not needed.
        pcap_filename = os.path.join(OUTPUT_DIR, f"{interface_name}-({packet_time_started})-({packet_time_ended}).pcap")
        wrpcap(pcap_filename, captured_packets)

    except Exception as e:
        print(f"Error capturing traffic on {interface_name}: {e}")
    
    return pcap_filename


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


def packet_to_db(pcap_filename, db_config):
    """Inserts packet data into the database."""
    # Connect to the database
    connection = mysql.connect(**db_config)
    cursor = connection.cursor()

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
        insert_query = """
        INSERT INTO captured_packets (timestamp, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port, ethernet_type, network_protocol, transport_protocol, application_protocol, payload)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        try:
            # Execute the insertion query
            cursor.execute(f"USE network")
            cursor.execute(insert_query, (timestamp, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port, ethernet_type, network_protocol, transport_protocol, application_protocol, payload))
            connection.commit()
            print("Packet successfully inserted into database.")
        except mysql.Error as err:
            print(f"Error inserting packet into database DETAILS: {err}")

    # Close the database connection
    cursor.close()


def begin_capture(database_name, table_name, interface_name, db_config):
    port_to_dict()
    pcap_filename = capture_traffic(interface_name, db_config)
    packet_to_db(pcap_filename, db_config)