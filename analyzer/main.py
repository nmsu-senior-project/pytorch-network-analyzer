"""
 _____       _                 _       _   _      _                      _    
|  __ \     | |               | |     | \ | |    | |                    | |   
| |__) |   _| |_ ___  _ __ ___| |__   |  \| | ___| |___      _____  _ __| | __
|  ___/ | | | __/ _ \| '__/ __| '_ \  | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /
| |   | |_| | || (_) | | | (__| | | | | |\  |  __/ |_ \ V  V / (_) | |  |   < 
|_|    \__, |\__\___/|_|  \___|_| |_| |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\
        __/ |                                                                 
       |___/                                                                  
                      _                    
    /\               | |                   
   /  \   _ __   __ _| |_   _ _______ _ __ 
  / /\ \ | '_ \ / _` | | | | |_  / _ \ '__|
 / ____ \| | | | (_| | | |_| |/ /  __/ |   
/_/    \_\_| |_|\__,_|_|\__, /___\___|_|   
                         __/ |             
                        |___/  
"""

import re
import os, sys
import threading
import time
import mysql.connector as mysql

from datetime import datetime

from scapy.layers.inet6 import IPv6
from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP, Raw

"""
  ____ _       _           _    ____                _              _           _____                 _   _                   
 / ___| | ___ | |__   __ _| |  / ___|___  _ __  ___| |_ __ _ _ __ | |_ ___    |  ___|   _ _ __   ___| |_(_) ___  _ __  ___   
| |  _| |/ _ \| '_ \ / _` | | | |   / _ \| '_ \/ __| __/ _` | '_ \| __/ __|   | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|  
| |_| | | (_) | |_) | (_| | | | |__| (_) | | | \__ \ || (_| | | | | |_\__ \_  |  _|| |_| | | | | (__| |_| | (_) | | | \__ \_ 
 \____|_|\___/|_.__/ \__,_|_|  \____\___/|_| |_|___/\__\__,_|_| |_|\__|___( ) |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___( )
                                                                          |/                                              |/ 
__     __         _       _     _                             _   ____  ____     ____             __ _       
\ \   / /_ _ _ __(_) __ _| |__ | | ___  ___    __ _ _ __   __| | |  _ \| __ )   / ___|___  _ __  / _(_) __ _ 
 \ \ / / _` | '__| |/ _` | '_ \| |/ _ \/ __|  / _` | '_ \ / _` | | | | |  _ \  | |   / _ \| '_ \| |_| |/ _` |
  \ V / (_| | |  | | (_| | |_) | |  __/\__ \ | (_| | | | | (_| | | |_| | |_) | | |__| (_) | | | |  _| | (_| |
   \_/ \__,_|_|  |_|\__,_|_.__/|_|\___||___/  \__,_|_| |_|\__,_| |____/|____/   \____\___/|_| |_|_| |_|\__, |
                                                                                                       |___/ 
"""

#Capture, Database, and Scapy Constants
DATABASE_NAME = "network"
TABLE_NAME = "captured_packets"
INTERFACE_NAME = "Wi-Fi"

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

DB_CONFIG_3 = {
    'user': 'user3',
    'password': 'password3',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

# Analysis Constants
PACKET_LIMIT = 1000
TIMEOUT = 30  # seconds
OUTPUT_DIR = "pcap_files"  # Output directory for PCAP files
os.makedirs(OUTPUT_DIR, exist_ok=True)
# Common VPN protocols for packet analysis and detection
VPN_PROTOCOLS = ["OpenVPN", "IKEv2", "L2P2", "PPTP", "WireGuard", "SSTP"]

# Global variables
pcap_filename = None


#-------------------------------------------------------
# Functions to connect and close the database connection
#-------------------------------------------------------

def connect_to_db(db_config):
    connection = mysql.connect(**db_config)
    cursor = connection.cursor()
    return cursor, connection


def close_db_connection(cursor, connection):
    if cursor:
        cursor.close()
    if connection:
        connection.close()


# --------------------------------------------------------
# Functions to fetch and certain data from database tables
# --------------------------------------------------------

def fetch_boolean_status(cursor, tb_name, col_name):
    cursor.execute(f"SELECT * FROM {tb_name} WHERE {col_name} = 0;")
    result = cursor.fetchone()
    if result is not None:
        return False
    return True


def fetch_and_check_primary_key(cursor, sql_command):
    cursor.execute(f"{sql_command}")
    result = cursor.fetchone()
    if result is not None:
        return False
    return True


def fetch_and_compare(cursor, data, sql_command, values):
    cursor.execute(f"{sql_command}", values)
    result = cursor.fetchone()
    if result is not None:
        queried_data = result[0]
        if queried_data != data:
            return True
    return False


def update_where(cursor, connection, sql_command, values):
    cursor.execute(f"{sql_command}", values)
    connection.commit()


def update_where_and(cursor, connection, tb_name, col_name, pkid, data, values):
    cursor.execute(f"UPDATE {tb_name} SET {col_name} = %s WHERE {pkid} = %s AND {data} = %s;", values)
    connection.commit()


def execute_and_commit(cursor, connection, sql_command, values):
    cursor.execute(f"{sql_command}", values)
    connection.commit()


# --------------------------------------------------------------
# Function to create the database and tables in the MySQL server
# --------------------------------------------------------------

def create_database_and_tables():
    cursor, connection = connect_to_db(DB_CONFIG_1)
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DATABASE_NAME}")
        cursor.execute(f"USE {DATABASE_NAME}")

        # Create tables for the network analyzer
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
                last_known_ip VARCHAR(45),
                first_seen VARCHAR(50),
                last_seen VARCHAR(50),
                manufacturer VARCHAR(255),
                last_known_location VARCHAR(255),
                FOREIGN KEY (last_known_ip) REFERENCES ip_addresses(ip_address) ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS nic_previous_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                mac_address VARCHAR(17),
                ip_address VARCHAR(45),
                first_seen VARCHAR(50),
                last_seen VARCHAR(50),
                FOREIGN KEY (mac_address) REFERENCES nic_record(mac_address) ON DELETE CASCADE,
                FOREIGN KEY (ip_address) REFERENCES ip_addresses(ip_address) ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyzed_packets (
                id INT Primary Key,
                packet_size INT,
                is_vpn TINYINT DEFAULT 0,
                is_arp TINYINT DEFAULT 0,
                FOREIGN KEY (id) REFERENCES captured_packets(id) ON DELETE CASCADE
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
            CREATE TABLE IF NOT EXISTS nic_stats (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nic VARCHAR(17),
                last_updated VARCHAR(50),
                is_source TINYINT DEFAULT 0,
                sent_packet_count INT DEFAULT 0,
                received_packet_count INT DEFAULT 0,
                sent_arp_count INT,
                FOREIGN KEY (nic) REFERENCES nic_record(mac_address) ON DELETE SET NULL
            )
        """)  

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_stats (
                id INT AUTO_INCREMENT PRIMARY KEY,
                stat_name VARCHAR(255),
                average_packet_size FLOAT,
                mean_packet_size FLOAT,
                average_packet_rate FLOAT,
                mean_packet_rate FLOAT,
                total_packets INT,
                peak_packet_rate FLOAT,
                peak_packet_rate_time VARCHAR(50),
                peak_bandwidth FLOAT,
                peak_bandwidth_time VARCHAR(50),
                most_common_protocol VARCHAR(10),
                most_common_source_ip VARCHAR(45),
                most_common_destination_ip VARCHAR(45),
                packet_error_rate FLOAT,
                duplicate_packet_amount INT,
                duplication_source_ip VARCHAR(45),
                duplication_destination_ip VARCHAR(45),
                started_calculation VARCHAR(50),
                last_calculation VARCHAR(50),
                time_period VARCHAR(10)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS baselines (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nic VARCHAR(17),
                baseline_type VARCHAR(255),
                established_time VARCHAR(50),
                ended_time VARCHAR(50),
                last_updated VARCHAR(50),
                packet_count INT,
                average_packet_size FLOAT,
                mean_packet_size FLOAT,
                average_packet_rate FLOAT,
                mean_packet_rate FLOAT,
                peak_packet_rate FLOAT,
                finalized TINYINT DEFAULT 0,
                FOREIGN KEY (nic) REFERENCES nic_record(mac_address) ON DELETE SET NULL
            )
        """)
    except mysql.Error as err:
        print(f"Error creating database or tables: {err}")
        sys.exit()
    finally:
        close_db_connection(cursor, connection)


"""
  ____            _                    _   _      _                      _    
 / ___|__ _ _ __ | |_ _   _ _ __ ___  | \ | | ___| |___      _____  _ __| | __
| |   / _` | '_ \| __| | | | '__/ _ \ |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /
| |__| (_| | |_) | |_| |_| | | |  __/ | |\  |  __/ |_ \ V  V / (_) | |  |   < 
 \____\__,_| .__/ \__|\__,_|_|  \___| |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\
           |_|                                                                
 _____           __  __ _        ____            _        _       
|_   _| __ __ _ / _|/ _(_) ___  |  _ \ __ _  ___| | _____| |_ ___ 
  | || '__/ _` | |_| |_| |/ __| | |_) / _` |/ __| |/ / _ \ __/ __|
  | || | | (_| |  _|  _| | (__  |  __/ (_| | (__|   <  __/ |_\__ \
  |_||_|  \__,_|_| |_| |_|\___| |_|   \__,_|\___|_|\_\___|\__|___/

"""

def determine_protocol(packet):
    """
    Function to determine the protocol of the packet by
    extracting layer information from the packet.
    
    Returns an array of protocol names that are found
    in the packet.
    """

    IGNORED_KEYWORDS = ['Padding', 'Raw', 'Router Alert']

    def sanitize_string(content):
        pass
        return re.sub(r'[^a-zA-Z0-9\s]', '', content).strip()

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

    for protocol_section in matches[:4]:
        for line in protocol_section.splitlines():
            if line.strip().startswith("###["):
                protocol_name = line.strip()[4:-3].strip()
                protocol_name = sanitize_string(protocol_name)
                if protocol_name not in IGNORED_KEYWORDS:
                    protocol_array.append(protocol_name)
            else:
                sanitized_line = sanitize_string(line.strip())
                if sanitized_line not in IGNORED_KEYWORDS:
                    protocol_array.append(sanitized_line)

    return protocol_array


# ---------------------------------------------------------------------- #
# Function to insert packet data into the database captured_packets table.
# ---------------------------------------------------------------------- #

def packet_to_db():
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

        payload = bytes(packet[Raw].load) if Raw in packet else None

        insert_query = (
            f"INSERT INTO {TABLE_NAME} (timestamp, source_mac, destination_mac, source_ip, destination_ip, "
            f"source_port, destination_port, ethernet_type, network_protocol, transport_protocol, "
            f"application_protocol, payload) "
            f"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        )

        try:
            cursor.execute(f"USE {DATABASE_NAME}")
            cursor.execute(insert_query, (
                timestamp, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port,
                ethernet_type, network_protocol, transport_protocol, application_protocol, payload))
            connection.commit()
        except mysql.Error as err:
            print(f"Error inserting packet into database DETAILS: {err}")

    close_db_connection(cursor, connection)


# ----------------------------------------------------------- #
# Function to capture network traffic and store in a pcap file.
# ----------------------------------------------------------- #

def capture_traffic():
    """Capture network traffic on the specified interface and store the packets in a pcap file."""
    global pcap_filename

    while True:
        start_time = time.time()
        packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")
        captured_packets = []
        packet_count = 0
        try:
            def packet_pcap(pkt):
                nonlocal packet_count
                packet_count += 1
                captured_packets.append(pkt)

            sniff(iface=INTERFACE_NAME, prn=packet_pcap, timeout=TIMEOUT, stop_filter=lambda _: packet_count == PACKET_LIMIT)

            packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
            print(f"Capture in {time.time() - start_time} seconds.")
            print(f"Total packet count: {str(packet_count)} \n")

            pcap_filename = os.path.join(OUTPUT_DIR, f"{INTERFACE_NAME}-({packet_time_started})-({packet_time_ended}).pcap")
            wrpcap(pcap_filename, captured_packets)

        except Exception as e:
            print(f"Error capturing traffic on {INTERFACE_NAME}: {e}")
        finally:
            packet_to_db()


"""
    _                _                 _   _      _                      _    
   / \   _ __   __ _| |_   _ _______  | \ | | ___| |___      _____  _ __| | __
  / _ \ | '_ \ / _` | | | | |_  / _ \ |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /
 / ___ \| | | | (_| | | |_| |/ /  __/ | |\  |  __/ |_ \ V  V / (_) | |  |   < 
/_/   \_\_| |_|\__,_|_|\__, /___\___| |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\
                       |___/                                                  
 ____            _        _       
|  _ \ __ _  ___| | _____| |_ ___ 
| |_) / _` |/ __| |/ / _ \ __/ __|
|  __/ (_| | (__|   <  __/ |_\__ \
|_|   \__,_|\___|_|\_\___|\__|___/

"""

# -------------------------------------------------------------------------------------- #
# Secondary functions to analyze NIC and IP addresses and store the information in the DB.
# -------------------------------------------------------------------------------------- #

def is_nic_new(mac_address, cursor):
    # Check if the NIC is new by checking if the MAC address exists in the nic_record table
    return fetch_and_check_primary_key(cursor, f"SELECT * FROM nic_record WHERE mac_address = '{mac_address}';")


def has_ip_changed(mac_address, ip_address, cursor):
    # Check if the IP address has changed for the NIC by comparing the last known IP address
    return fetch_and_compare(cursor, ip_address, "SELECT last_known_ip FROM nic_record WHERE mac_address = %s;", (mac_address,))


def is_ip_new(ip_address, cursor):
    # Check if the IP address is new by checking if the IP address exists in the ip_addresses table
    return fetch_and_check_primary_key(cursor, f"SELECT * FROM ip_addresses WHERE ip_address = '{ip_address}';")


def check_for_vpn(protocol):
    # Check if the packet contains a VPN protocol
    return protocol in VPN_PROTOCOLS


# -------------------------------------- #
# Primary functions to analyze the packets.
# -------------------------------------- #

def analyze_packet():
    # Placeholder for packet analysis
    pass


def analyze_nic(mac_address, ip_address, timestamp, cursor, connection):
    # Analyze the NIC and store the relavent information about it in the nic tables
    if mac_address:
        try:
            if is_nic_new(mac_address, cursor):
                execute_and_commit(cursor, connection, "INSERT INTO nic_record (mac_address, first_seen) VALUES (%s, %s);", (mac_address, timestamp))
                execute_and_commit(cursor, connection, "INSERT INTO nic_stats (nic, last_updated) VALUES (%s, %s);", (mac_address, timestamp))
        except mysql.Error as err:
            print(f"Error: {err}")
        finally:
            execute_and_commit(cursor, connection, "UPDATE nic_record SET last_seen = %s WHERE mac_address = %s;", (timestamp, mac_address))


def analyze_ip(mac_address, ip_address, timestamp, cursor, connection):
    # Analyze the IP address and store the relavent information about it in the ip tables
    if ip_address:
        try:
            if is_ip_new(ip_address, cursor):
                is_ipv6 = 1 if ":" in ip_address else 0
                execute_and_commit(cursor, connection, "INSERT INTO ip_addresses (ip_address, is_ipv6, first_seen) VALUES (%s, %s, %s);", (ip_address, is_ipv6, timestamp))
                execute_and_commit(cursor, connection, "UPDATE nic_record SET last_known_ip = %s WHERE mac_address = %s;", (ip_address, mac_address))
                execute_and_commit(cursor, connection, "INSERT INTO nic_previous_ips (mac_address, ip_address, first_seen, last_seen) VALUES (%s, %s, %s, %s);", (mac_address, ip_address, timestamp, timestamp))
            if has_ip_changed(mac_address, ip_address, cursor):
                execute_and_commit(cursor, connection, "UPDATE nic_record SET last_known_ip = %s WHERE mac_address = %s;", (ip_address, mac_address))
                execute_and_commit(cursor, connection, "UPDATE ip_addresses SET last_seen = %s WHERE ip_address = %s;", (timestamp, ip_address))
                execute_and_commit(cursor, connection, "INSERT INTO nic_previous_ips (mac_address, ip_address, first_seen, last_seen) VALUES (%s, %s, %s, %s);", (mac_address, ip_address, timestamp, timestamp))
        except mysql.Error as err:
            print(f"Error: {err}")
        finally:
            execute_and_commit(cursor, connection, "UPDATE ip_addresses SET last_seen = %s WHERE ip_address = %s;", (timestamp, ip_address))
            execute_and_commit(cursor, connection, "UPDATE nic_previous_ips SET last_seen = %s WHERE mac_address = %s AND ip_address = %s;", (timestamp, mac_address, ip_address))


# ----------------------------------------------------------------------------- #
# Function to analyze network packets and modify the information in the database.
# ----------------------------------------------------------------------------- #

def packet_analysis():
    while True:
        try:
            cursor, connection = connect_to_db(DB_CONFIG_2)
            cursor.execute(f"USE {DATABASE_NAME}")
            cursor.execute("SELECT * FROM captured_packets WHERE analyzed = 0 ORDER BY id;")
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

                    analyze_packet()

                    analyze_nic(source_mac, source_ip, timestamp, cursor, connection)
                    analyze_nic(destination_mac, destination_ip, timestamp, cursor, connection)

                    analyze_ip(source_mac, source_ip, timestamp, cursor, connection)
                    analyze_ip(destination_mac, destination_ip, timestamp, cursor, connection)
                    
                    execute_and_commit(cursor, connection, "UPDATE nic_stats SET sent_packet_count = sent_packet_count + 1 WHERE nic = %s;", (source_mac,))
                    if destination_mac:
                        execute_and_commit(cursor, connection, "UPDATE nic_stats SET received_packet_count = received_packet_count + 1 WHERE nic = %s;", (destination_mac,))
                    execute_and_commit(cursor, connection, "UPDATE captured_packets SET analyzed = 1 WHERE id = %s;", (packet_id,))

        except mysql.Error as err:
            print(f"Error: {err}")
        finally:
            close_db_connection(cursor, connection)


"""
 ____                 _ _              ____            _   _             
| __ )  __ _ ___  ___| (_)_ __   ___  / ___|  ___  ___| |_(_) ___  _ __  
|  _ \ / _` / __|/ _ \ | | '_ \ / _ \ \___ \ / _ \/ __| __| |/ _ \| '_ \ 
| |_) | (_| \__ \  __/ | | | | |  __/  ___) |  __/ (__| |_| | (_) | | | |
|____/ \__,_|___/\___|_|_|_| |_|\___| |____/ \___|\___|\__|_|\___/|_| |_|
                                                                         
"""

def has_packet_count_changed(mac_address, total_packet_count, cursor):
    return fetch_and_compare(cursor, total_packet_count, "SELECT total_packet_count FROM nic_record WHERE mac_address = %s;", (mac_address,))

def baseline_analysis():
    while True:
        cursor, connection = connect_to_db(DB_CONFIG_3)
        cursor.execute(f"USE {DATABASE_NAME}")
        try:
            time.sleep(30) #Ensures the server does not get overloaded with requests

            cursor.execute("SELECT baseline_type FROM baselines WHERE finalized = 0 AND baseline_type = 'daily';")
            rows = cursor.fetchall()
            if rows is not None:
                for row in rows:
                    nic = row[1]
                    # if has_packet_count_changed(mac_address, total_packet_count, cursor):
            else:
                continue #if None, continue to next iteration
                
        except mysql.Error as err:
            print(f"Error executing SQL query: {err}")
        finally:
            close_db_connection(cursor, connection)


"""
 __  __       _         _____                 _   _             
|  \/  | __ _(_)_ __   |  ___|   _ _ __   ___| |_(_) ___  _ __  
| |\/| |/ _` | | '_ \  | |_ | | | | '_ \ / __| __| |/ _ \| '_ \ 
| |  | | (_| | | | | | |  _|| |_| | | | | (__| |_| | (_) | | | |
|_|  |_|\__,_|_|_| |_| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|

"""

def main():
    create_database_and_tables()

    capture_thread = threading.Thread(target=capture_traffic)
    analysis_thread = threading.Thread(target=packet_analysis)
    baseline_thread = threading.Thread(target=baseline_analysis)

    capture_thread.start()
    analysis_thread.start()
    baseline_thread.start()

    capture_thread.join()
    analysis_thread.join()
    baseline_thread.join()


if __name__ == '__main__':
    main()