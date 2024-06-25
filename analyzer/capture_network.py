import logging
import os,sys, time, subprocess
from analyze_network import begin_scan

from datetime import datetime

import mysql.connector as mysql
from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, Raw
from scapy.arch.windows import get_windows_if_list

# Constants
PACKET_LIMIT = 100000
TIMEOUT = 600 # 10 minutes
OUTPUT_DIR = "pcap_files"

os.makedirs(OUTPUT_DIR, exist_ok=True)

#Array to store captured packets
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


# def truncate_table(cursor, tb_name):
#     cursor.execute(f"TRUNCATE TABLE {tb_name};")


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
            source_ip VARCHAR(45),
            destination_ip VARCHAR(45),
            source_port INT,
            destination_port INT,
            protocol VARCHAR(20), -- Increased size to accommodate longer protocol names
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


def packet_to_db(packet, db_config):
    insert_query = """
    INSERT INTO captured_packets (timestamp, source_mac, source_ip, destination_ip, source_port, destination_port, protocol, payload, analyzed)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0)
    """

    # Extract necessary fields from the packet
    source_mac = packet[Ether].src if Ether in packet else None
    timestamp = datetime.now()
    source_ip = packet[IP].src if IP in packet else None
    destination_ip = packet[IP].dst if IP in packet else None

    if IP in packet:
        ip_protocol = packet[IP].proto
        if ip_protocol == 6:
            protocol = "TCP"
        elif ip_protocol == 17:
            protocol = "UDP"
        elif ip_protocol == 1:
            protocol = "ICMP"
        else:
            protocol = f"IP Protocol {ip_protocol}"
    elif Ether in packet:
        protocol = "Ethernet"
    else:
        protocol = "Unknown"

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
    else:
        source_port = None
        destination_port = None

    payload = bytes(packet[Raw].load) if Raw in packet else None

    # Connect to the database
    connection = mysql.connect(**db_config)
    cursor = connection.cursor()

    try:
        # Execute the insertion query
        cursor.execute(insert_query, (timestamp, source_mac, source_ip, destination_ip, source_port, destination_port, protocol, payload))
        connection.commit()
        logging.info("Packet successfully inserted into database.")
    except mysql.Error as err:
        logging.error(f"Error inserting packet into database: {err}")
    finally:
        cursor.close()
        connection.close()


def capture_traffic(interface_name, db_config):
    """Captures traffic on the specified interface and stores packets in a list."""
    print_divider(80, 1)
    time.sleep(2)
    print(f"Starting capture on interface {interface_name}:")
    print_divider(41, 0)
    packet_count = 0

    try:
        # Define a callback function to store each packet in the captured_packets list
        def store_packet(pkt):
            nonlocal packet_count
            packet_count += 1
            captured_packets.append(pkt)
            packet_to_db(pkt, db_config)

            if packet_count >= PACKET_LIMIT:
                return False  # Returning False stops the packet capture

        # Start packet capture, using the store_packet callback to store each packet
        packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")
        time.sleep(2)
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
        database_name = input("Enter database name you need to create or use: ")

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
        interface_name = input("Enter interface name from the list above (or 'q' to quit): ")
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
    main()