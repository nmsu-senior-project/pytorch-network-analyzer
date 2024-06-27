import logging
import re
import os,sys, time, subprocess
from analyze_network import begin_scan

from datetime import datetime

import pandas as pd
import mysql.connector as mysql
import scapy.all as scapy
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

def read_specific_lines(filename, line_numbers):
  credentials = {}
  try:
    with open(filename, 'r') as file:
      for line_number in line_numbers:
        # Check for valid line number (within file size)
        if line_number <= 0 or line_number > len(file.readlines()):
          print(f"Invalid line number: {line_number}")
          return None

        # Seek to the beginning of the desired line
        file.seek(0)  # Reset file pointer to beginning

        # Skip lines before the desired line
        for _ in range(line_number - 1):
          file.readline()

        # Read and process the current line
        line = file.readline().strip()
        if line:  # Check if line is not empty
          key, value = line.split(':')
          credentials[key.strip()] = value.strip()

  except FileNotFoundError:
    print(f"The file {filename} was not found.")
    return None

  # Check if any lines were successfully read
  if not credentials:
    print(f"No valid lines found for numbers: {line_numbers}")
    return None

  return credentials

# Example usage
credentials = read_specific_lines('credentials.txt', [1, 2])

if credentials:
  db_user = credentials.get('db_user')
  db_pass = credentials.get('db_pass')
else:
  print("Failed to read credentials.")


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



def create_database_and_tables(cursor, db_name, tb_name):
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")

    cursor.execute(f"USE {db_name}")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_addresses (
            ip_address VARCHAR(45) PRIMARY KEY,
            is_ipv6 TINYINT DEFAULT 0,
            first_seen DATETIME,
            last_seen DATETIME,
            hostname VARCHAR(255),
            subnet VARCHAR(45),
            lease_expires DATETIME,
            last_known_location VARCHAR(255)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS captured_packets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME NOT NULL,
            source_mac VARCHAR(17),
            destination_mac VARCHAR(17),
            source_ip VARCHAR(45),
            destination_ip VARCHAR(45),
            source_port INT,
            destination_port INT,
            ethernet_type VARCHAR(50),
            network_protocol VARCHAR(50),
            transport_protocol VARCHAR(50), -- Increased size to accommodate longer protocol names
            application_protocol VARCHAR(50),
            payload BLOB,
            analyzed TINYINT DEFAULT 0
        );
    """)

    cursor.execute("""
        -- Table for storing NIC information
        CREATE TABLE IF NOT EXISTS NIC_record (
            mac_address VARCHAR(17) PRIMARY KEY,
            manufacturer VARCHAR(255),
            ip_addresses VARCHAR(45),
            first_seen DATETIME,
            last_seen DATETIME,
            last_known_location VARCHAR(255),
            previous_locations VARCHAR(255),
            FOREIGN KEY (ip_addresses) REFERENCES ip_addresses(ip_address) ON DELETE SET NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyzed_packets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            packet_id INT,
            source_NIC VARCHAR(17),
            is_vpn TINYINT DEFAULT 0,
            is_malicious TINYINT DEFAULT 0,
            is_encrypted TINYINT DEFAULT 0,
            anomaly_score FLOAT,
            analysis_details TEXT,
            destination_NIC VARCHAR(17),
            FOREIGN KEY (packet_id) REFERENCES captured_packets(id) ON DELETE CASCADE,
            FOREIGN KEY (source_NIC) REFERENCES NIC_record(mac_address) ON DELETE CASCADE,
            FOREIGN KEY (destination_NIC) REFERENCES NIC_record(mac_address) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            associated_NIC VARCHAR(17),
            device_name VARCHAR(255),
            device_type VARCHAR(255),
            operating_system VARCHAR(255),
            manufacturer VARCHAR(255),
            model VARCHAR(255),
            serial_number VARCHAR(255),
            location VARCHAR(255),
            purchase_date DATE,
            FOREIGN KEY (associated_NIC) REFERENCES NIC_record(mac_address) On DELETE SET NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id INT AUTO_INCREMENT PRIMARY KEY,
            stat_name VARCHAR(255),
            average_packet_size FLOAT,
            mean_packet_size FLOAT,
            average_packet_rate FLOAT,
            mean_packet_rate FLOAT,
            total_packets INT,
            peak_packet_rate FLOAT,
            peak_packet_rate_time DATETIME,
            peak_bandwidth FLOAT,
            peak_bandwidth_time DATETIME,
            most_common_protocol VARCHAR(10),
            most_common_source_ip VARCHAR(45),
            most_common_destination_ip VARCHAR(45),
            packet_error_rate FLOAT,
            duplicate_packet_amount INT,
            duplication_source_ip VARCHAR(45),
            duplication_destination_ip VARCHAR(45),
            started_calculation DATETIME,
            last_calculation DATETIME,
            time_period VARCHAR(10)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS baselines (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nic_mac_address VARCHAR(17),
            stat_name VARCHAR(255),
            average_value FLOAT,
            max_value FLOAT,
            min_value FLOAT,
            standard_deviation FLOAT,
            time_period VARCHAR(10),
            established_on DATETIME,
            FOREIGN KEY (nic_mac_address) REFERENCES NIC_record(mac_address) ON DELETE SET NULL
        );
    """)

  
def determine_protocol(packet):
    """Determines the protocol of the packet based on the layers present."""
    IGNORED_KEYWORDS = ['Padding', 'Raw', 'Router Alert']

    def sanitize_string(content):
        return re.sub(r'[^a-zA-Z0-9\s]', '', content).strip()

    packet_info = packet.show(dump=True)
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


def packet_to_db(packet, db_config):
    """Inserts packet data into the database."""

    protocol_array = determine_protocol(packet)

    timestamp = datetime.now()
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

    # Connect to the database
    connection = mysql.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Execute the insertion query
        cursor.execute(insert_query, (timestamp, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port, ethernet_type, network_protocol, transport_protocol, application_protocol, payload))
        connection.commit()
        print("Packet successfully inserted into database.")
    except mysql.Error as err:
        print(f"Error inserting packet into database: {err}")
    finally:
        cursor.close()
        connection.close()


def insert_from_pcap(pcap_filename, db_config):
    # Read packets from PCAP file
    packets = rdpcap(pcap_filename)

    # Connect to the database
    connection = mysql.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Iterate through each packet and insert into the database
        for packet in packets:
            packet_to_db(packet, db_config)

    except mysql.Error as err:
        print(f"Error inserting packets into database: {err}")
    finally:
        cursor.close()
        connection.close()


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
        sniff(iface=interface_name, prn=store_packet, timeout=TIMEOUT, stop_filter=lambda _: packet_count >= PACKET_LIMIT)
        
        packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
        print("Ended capture at " + packet_time_ended)
        print(f"Total packet count: {str(packet_count)} \n")

        # Write captured packets to a PCAP file
        # FYI: Comment these three lines if PCAP creation is not needed.
        pcap_filename = os.path.join(OUTPUT_DIR, f"{interface_name}-({packet_time_started})-({packet_time_ended}).pcap")
        wrpcap(pcap_filename, captured_packets)
        insert_from_pcap(pcap_filename, db_config)
        print(f"Captured packets written to {pcap_filename}")
        print("Capture completed.")
    except Exception as e:
        print(f"Error capturing traffic on {interface_name}: {e}")


def main():
    connection = None

    # Connect to database
    try:
        db_config = {
            'user': db_user,
            'password': db_pass,
            'host': 'localhost',
            'port': 3306
        }
        connection = mysql.connect(**db_config)
        cursor = connection.cursor()
        print_divider(80, 1)
        database_name = 'network' #input("Enter database name you need to create or use: ")

        #FYI: Uncomment these lines if you want to list all tables in the database and choose one
        # cursor.execute(f"USE {database_name}")
        # cursor.execute("SHOW TABLES")
        # tables = cursor.fetchall()
        # print_divider(80, 1)
        # print("All avaliable tables:")

        # for (table_name,) in tables:
        #     print(table_name)

        # print_divider(0,1)
        # table_name = input("Enter table name you need to create or use: ")
        table_name = "captured_packets"

        create_database_and_tables(cursor, database_name, table_name)
        cursor.close()
        connection.close()
    except mysql.Error as err:
        print(f"Error: {err}")
        sys.exit()

    # Prompt user for interface selection by name and start capture
    print_divider(80, 1)
    interfaces = get_windows_if_list()
    print("Available interfaces:")
    for interface in interfaces:
        interface_name = interface['name']
        interface_ips = ', '.join(interface['ips'])
        print(f"Name: {interface_name}, IPs: {interface_ips}")

    while True:
        print_divider(0, 1)
        interface_name = "Ethernet 2" #input("Enter interface name from the list above (or 'q' to quit): ")
        if interface_name.lower() == 'q':
            break
        if any(interface['name'] == interface_name for interface in interfaces):
            db_config['database'] = f'{database_name}'
            capture_traffic(interface_name, db_config)

            # subprocess.run(['python', 'scan_network_traffic.py', f'{database_name}', f'{table_name}'])
            break  # Exit after capturing on one interface
        else:
            print("Invalid interface name. Please try again.")

    #Start the scanning packet process by opening analyze_network.py file
    begin_scan(database_name, table_name)
    sys.exit()

if __name__ == "__main__":
    port_to_dict()
    main()