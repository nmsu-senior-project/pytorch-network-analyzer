import re
import os, sys
import threading
import time
import mysql.connector as mysql

from datetime import datetime

from scapy.layers.inet6 import IPv6
from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP, Raw

"""#################################################################"""
"""Configurations, setup, shared functions for the network analyzer."""
"""#################################################################"""

#Database and Scapy Constants
DATABASE_NAME = "network"
TABLE_NAME = "captured_packets"

INTERFACE_NAME = "Ethernet 2"

DB_CONFIG_1 = {
    'user': 'user1',
    'password': 'password1', 
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

DB_CONFIG_2 = {
    'user': 'user2',
    'password': 'password2', 
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

#Analysis Constants
PACKET_LIMIT = 1000
TIMEOUT = 30 #seconds
OUTPUT_DIR = "pcap_files"
os.makedirs(OUTPUT_DIR, exist_ok=True)

VPN_PROTOCOLS = ["OpenVPN", "IKEv2", "L2P2", "PPTP", "WireGuard", "SSTP"]

#Global variables
pcap_filename = None


def connect_to_db(db_config):
    connection = mysql.connect(**db_config)
    cursor = connection.cursor()

    return cursor, connection


def close_db_connection(cursor, connection):
    if cursor:
        cursor.close()
    if connection:
        connection.close()


def create_database_and_tables():
    cursor, connection = connect_to_db(DB_CONFIG_1)
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DATABASE_NAME}")
        cursor.execute(f"USE {DATABASE_NAME}")

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
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS captured_packets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp VARCHAR(50),
                source_mac VARCHAR(17),
                destination_mac VARCHAR(17),
                source_ip VARCHAR(45),
                destination_ip VARCHAR(45),
                source_port INT,
                destination_port INT,
                ethernet_type VARCHAR(50),
                network_protocol VARCHAR(50),
                transport_protocol VARCHAR(50),
                application_protocol VARCHAR(100),
                payload BLOB,
                analyzed TINYINT DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS nic_record (
                mac_address VARCHAR(17) PRIMARY KEY,
                manufacturer VARCHAR(255),
                last_known_ip VARCHAR(45),
                previous_ip_list VARCHAR(45),
                first_seen DATETIME,
                last_seen DATETIME,
                last_known_location VARCHAR(255),
                previous_locations VARCHAR(255),
                FOREIGN KEY (previous_ip_list) REFERENCES ip_addresses(ip_address) ON DELETE SET NULL
            )
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
                FOREIGN KEY (source_NIC) REFERENCES nic_record(mac_address) ON DELETE CASCADE,
                FOREIGN KEY (destination_NIC) REFERENCES nic_record(mac_address) ON DELETE CASCADE
            )
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
                FOREIGN KEY (associated_NIC) REFERENCES nic_record(mac_address) On DELETE SET NULL
            )
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
            )
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
                FOREIGN KEY (nic_mac_address) REFERENCES nic_record(mac_address) ON DELETE SET NULL
            )
        """)

    except mysql.Error as err:
        print(f"Error creating database or tables: {err}")
        sys.exit()
    finally:
        close_db_connection(cursor, connection)


"""#####################################################################################"""
"""Function that captures network packets and stores them in a PCAP file and a database."""
"""#####################################################################################"""

def determine_protocol(packet):
    """Determines the protocol of the packet based on the layers present."""
    IGNORED_KEYWORDS = ['Padding', 'Raw', 'Router Alert']

    def sanitize_string(content):
        pass
        return re.sub(r'[^a-zA-Z0-9\s]', '', content).strip()

    #Mitigates timestamp error issues
    try:
        packet_info = packet.show(dump=True)
    except OSError as e:
        if e.errno == 22:
            return [], None
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


def packet_to_db():
    """Inserts packet data into the database."""

    # Connect to the database
    cursor, connection = connect_to_db(DB_CONFIG_1)

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
    
    close_db_connection(cursor, connection)


def capture_traffic():
    """Captures traffic on the specified interface and stores packets in a list."""
    global pcap_filename

    while True:
        start_time = time.time()
        packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")
        captured_packets = []
        packet_count = 0
        try:
            # # Define a callback function to store each packet in the captured_packets list
            def packet_pcap(pkt):
                nonlocal packet_count
                packet_count += 1
                captured_packets.append(pkt)


            #scan the network
            sniff(iface=INTERFACE_NAME, prn=packet_pcap, timeout=TIMEOUT, stop_filter=lambda _: packet_count == PACKET_LIMIT)
            
            packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
            print(f"Capture in {time.time() - start_time} seconds.")
            print(f"Total packet count: {str(packet_count)} \n")

            # Write captured packets to a PCAP file
            # FYI: Comment these three lines if PCAP creation is not needed.
            pcap_filename = os.path.join(OUTPUT_DIR, f"{INTERFACE_NAME}-({packet_time_started})-({packet_time_ended}).pcap")
            wrpcap(pcap_filename, captured_packets)

        except Exception as e:
            print(f"Error capturing traffic on {INTERFACE_NAME}: {e}")
        finally:
            packet_to_db()


"""#########################################################################################"""
"""Function that analyzes the captured network packets and stores the results in a database."""
"""#########################################################################################"""

def is_nic_new(mac_address, cursor):
    """Check if the NIC is being seen for the first time."""
    cursor.execute(f"SELECT * FROM nic_record WHERE mac_address = '{mac_address}';")
    result = cursor.fetchone()

    if result is not None:  # Check if result is not None (indicating NIC exists)
        return False
    return True  # NIC is new if no result found


def has_ip_changed(mac_address, ip_address, cursor):
    """Check if the IP address has changed for the NIC."""
    cursor.execute(f"SELECT last_known_ip FROM nic_record WHERE mac_address = '{mac_address}';")
    result = cursor.fetchone()
    if result:
        ip_addresses = result[0]
        cursor.execute(f"UPDATE nic_record SET ip_addresses = '{ip_addresses + ', ' + ip_address}' WHERE mac_address = '{mac_address}';")
        return ip_address not in ip_addresses
    return False


def is_ip_new(ip_address, cursor):
    """Check if the IP address is being seen for the first time."""
    cursor.execute(f"SELECT * FROM ip_addresses WHERE ip_address = '{ip_address}';")
    return cursor.fetchone() is None


def check_for_vpn(payload):
    """Check if any of the common VPN protocols are present in the payload."""
    for protocol in VPN_PROTOCOLS:
        if protocol == str(payload):
            return True, protocol
    return False, None


def begin_analysis():
    while True:
        try:
            # Connect to database
            cursor, connection = connect_to_db(DB_CONFIG_2)
             # Get unprocessed packets
            cursor.execute(f"USE {DATABASE_NAME}")
            cursor.execute(f"SELECT * FROM captured_packets WHERE analyzed = 0 ORDER BY id;")
            packets = cursor.fetchall()

            if packets:
                for packet in packets:
                    packet_id = packet[0]
                    timestamp = packet[1]
                    source_mac = packet[2]
                    destination_mac = packet[3]
                    source_ip = packet[4]
                    destination_ip = packet[5]
                    source_port = packet[6]
                    destination_port = packet[7]
                    ethernet_type = packet[8]
                    network_protocol = packet[9]
                    transport_protocol = packet[10]
                    application_protocol = packet[11]
                    payload = packet[12]

                    if is_nic_new(packet[2], cursor):
                        cursor.execute(f"INSERT INTO nic_record (mac_address, first_seen) VALUES (%s, %s);", (packet[2], packet[1]))
                        connection.commit()
                    elif has_ip_changed(packet[2], packet[4], cursor):
                        cursor.execute(f"UPDATE nic_record SET last_known_ip = '{packet[4]}' WHERE mac_address = '{packet[2]}';")
                        

                    # Check if the source IP is new
                    if is_ip_new(packet[4], cursor):
                        cursor.execute(f"INSERT INTO ip_addresses (ip_address, is_ipv6, first_seen) VALUES ('{packet[4]}', 0, '{packet[1]}');")
                    # Check if the destination IP is new
                    if is_ip_new(packet[5], cursor):
                        cursor.execute(f"INSERT INTO ip_addresses (ip_address, is_ipv6, first_seen) VALUES ('{packet[5]}', 0, '{packet[1]}');")

                    cursor.execute(f"UPDATE nic_record SET last_seen = '{packet[1]}' WHERE mac_address = '{packet[2]}';")
                    cursor.execute(f"UPDATE captured_packets SET analyzed = 1 WHERE id = {packet[0]};")

                    connection.commit()

        except mysql.Error as err:
            print(f"Error: {err}")             
        finally:
            close_db_connection(cursor, connection)


"""##################################################"""
"""Main function to run the network analyzer program."""
"""##################################################"""

def main():
    create_database_and_tables()

    capture_thread = threading.Thread(target=capture_traffic)
    analysis_thread = threading.Thread(target=begin_analysis)

    capture_thread.start()
    analysis_thread.start()

    capture_thread.join()
    analysis_thread.join()

if __name__ == '__main__':
    main()