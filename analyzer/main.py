"""
 ____        _                 _          
|  _ \ _   _| |_ ___  _ __ ___| |__       
| |_) | | | | __/ _ \| '__/ __| '_ \      
|  __/| |_| | || (_) | | | (__| | | |     
|_|    \__, |\__\___/|_|  \___|_| |_|     
       |___/                              
 _   _      _                      _      
| \ | | ___| |___      _____  _ __| | __  
|  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /  
| |\  |  __/ |_ \ V  V / (_) | |  |   <   
|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\                                         
    _                _                    
   / \   _ __   __ _| |_   _ _______ _ __ 
  / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 / ___ \| | | | (_| | | |_| |/ /  __/ |   
/_/   \_\_| |_|\__,_|_|\__, /___\___|_|   
                       |___/              
"""
import csv
import re
import os
import sys
import threading
import time
import mysql.connector as mysql

from datetime import datetime

from scapy.layers.inet6 import IPv6
from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP, Raw

"""
  ____ _       _           _  __     __    _                 
 / ___| | ___ | |__   __ _| | \ \   / /_ _| |_   _  ___  ___ 
| |  _| |/ _ \| '_ \ / _` | |  \ \ / / _` | | | | |/ _ \/ __|
| |_| | | (_) | |_) | (_| | |   \ V / (_| | | |_| |  __/\__ \
 \____|_|\___/|_.__/ \__,_|_|    \_/ \__,_|_|\__,_|\___||___/

All global constants and variables are defined here. These constants
and variables are used throughout the program for database connection,
packet analysis, and other functions. The constants and variables
defined here are used to configure the program and set up the database
and tables for the network analyzer.

There are three sets of database configurations defined here. This is
because the community edition of MySQL only allows a limited number of
connections. By defining three sets of database configurations, the
program can connect to three different databases simultaneously.

This is the location where you can change the database configuration,
values, and other settings for the network analyzer. You can also
define the packet analysis constants and other settings here.

Be careful when changing the constants and variables in this file, as
they are used throughout the program and changing them may affect the
functionality.

"""

# ----------------------------------- #
# Database, Scapy, Capture Constants.
# ----------------------------------- #

# MySQL Database Constants
DATABASE_NAME = "network"
TABLE_NAME = "captured_packets"

# Scapy uses this interface name for packet capture stage
INTERFACE_NAME = "enp3s0"

# Capture connection
DB_CONFIG_1 = {
    'user': 'user1',
    'password': 'password1',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

# Analysis connection
DB_CONFIG_2 = {
    'user': 'user2',
    'password': 'password2',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

# Baseline connection
DB_CONFIG_3 = {
    'user': 'user3',
    'password': 'password3',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

# Local record connection
DB_CONFIG_4 = {
    'user': 'user4',
    'password': 'password4',
    'host': 'localhost',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

# Capture Constants
PACKET_LIMIT = 1000  # Maximum number of packets to capture
TIMEOUT = 30  # Capture timeout in seconds

# Output directory for PCAP files
OUTPUT_DIR = "files"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ------------------ #
# Analysis Constants
# ------------------ #

# Common VPN protocols
VPN_PROTOCOLS = ["OpenVPN", "IKEv2", "L2P2", "PPTP", "WireGuard", "SSTP"]

# ---------------- #
# Global Variables
# ---------------- #

pcap_filename = None

pending_pcap_files = []
local_nic_record = []
pending_nic_record = []

pause_capture_inserts = False
not_analyzed_count = 0

"""
  ____ _       _           _                 
 / ___| | ___ | |__   __ _| |                
| |  _| |/ _ \| '_ \ / _` | |                
| |_| | | (_) | |_) | (_| | |                
 \____|_|\___/|_.__/ \__,_|_|                                                            
 _____                 _   _                 
|  ___|   _ _ __   ___| |_(_) ___  _ __  ___ 
| |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
|  _|| |_| | | | | (__| |_| | (_) | | | \__ \
|_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/

"""

# ------------------------------------------------------- #
# Functions to connect and close the database connection. #
# ------------------------------------------------------- #


def connect_to_db(db_config):
    connection = mysql.connect(**db_config)
    cursor = connection.cursor()
    return cursor, connection


def close_db_connection(cursor, connection):
    if cursor:
        cursor.close()
    if connection:
        connection.close()

# ----------------------------------------------------------------- #
# Functions to fetch and compare certain data from database tables. #
# ----------------------------------------------------------------- #


def fetch_boolean_status(cursor, tb_name, col_name):
    cursor.execute(f"SELECT * FROM {tb_name} WHERE {col_name} = 0;")
    result = cursor.fetchone()
    if result is not None:
        return False
    return True


def fetch_primary_key(cursor, sql_command):
    """Check if the primary key exists in a table."""
    cursor.execute(f"{sql_command}")
    result = cursor.fetchone()
    if result is not None:
        return False  # If the primary key exists
    return True


def fetch_count(cursor, sql_command):
    """Fetch the count of rows in a table."""
    cursor.execute(f"USE {DATABASE_NAME}")
    cursor.execute(f"{sql_command}")
    result = cursor.fetchone()
    return result[0]


def fetch_and_compare(cursor, data, sql_command, values):
    """Fetch and compare data from the queried database table."""
    cursor.execute(f"{sql_command}", values)
    result = cursor.fetchone()
    if result is not None:
        queried_data = result[0]
        if queried_data != data:
            return True
    return False


def update_where(cursor, sql_command, values):
    """Update the database table with the specified values."""
    cursor.execute(f"{sql_command}", values)


def update_where_and(cursor, tb_name, col_name, pkid, data, values):
    """Update the database table with the specified values and conditions."""
    cursor.execute(
        f"""
        UPDATE {tb_name}
            SET {col_name} = %s
            WHERE {pkid} = %s
            AND {data} = %s;
        """,
        values
    )


def execute_queries(cursor, queries):
    cursor.execute(f"USE {DATABASE_NAME}")

    try:
        for query in queries:
            cursor.execute(query)
    except mysql.Error as err:
        print(f"Error executing queries: {err} {query}")
        sys.exit()


"""
 ____  ____     ____             __ _       
|  _ \| __ )   / ___|___  _ __  / _(_) __ _ 
| | | |  _ \  | |   / _ \| '_ \| |_| |/ _` |
| |_| | |_) | | |__| (_) | | | |  _| | (_| |
|____/|____/   \____\___/|_| |_|_| |_|\__, |
                                      |___/

This function are responsible for creating the database and tables
for the network analyzer. The create_database_and_tables function will
create the database and tables for the network analyzer if they do not
already exist. The function will check if the database and tables exist
and create them if they do not.

These tables are essential for storing the network traffic data and
analyzing the packets. The tables will store information such as IP
addresses, MAC addresses, packet data, and other information that is
extracted from the network traffic.

This is the location where table and column names are defined. If you
want to change the table or column names, you can do so here. The
create_database_and_tables function will create the database and tables
with the specified names and columns.
"""


def create_database(cursor):
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DATABASE_NAME}")
    except mysql.Error as err:
        print(f"Error creating database: {err}")
        sys.exit()


def create_tables(cursor):
    global fetched_nic_record

    tables = [
        """
        CREATE TABLE IF NOT EXISTS csv_files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            file_name VARCHAR(255),
            start_datetime VARCHAR(50),
            end_datetime VARCHAR(50)
        )
        """,
        """
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
        """,
        """
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
        """,
        """
        CREATE TABLE IF NOT EXISTS nic_record (
            mac_address VARCHAR(17) PRIMARY KEY,
            last_known_ip VARCHAR(45),
            first_seen VARCHAR(50),
            last_seen VARCHAR(50),
            manufacturer VARCHAR(255),
            last_known_location VARCHAR(255),
            FOREIGN KEY (last_known_ip)
                REFERENCES ip_addresses(ip_address) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS nic_previous_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            mac_address VARCHAR(17),
            ip_address VARCHAR(45),
            first_seen VARCHAR(50),
            last_seen VARCHAR(50),
            FOREIGN KEY (mac_address)
                REFERENCES nic_record(mac_address) ON DELETE CASCADE,
            FOREIGN KEY (ip_address)
                REFERENCES ip_addresses(ip_address) ON DELETE SET NULL
        )
        """,
        """
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
            FOREIGN KEY (associated_NIC)
                REFERENCES nic_record(mac_address) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS nic_stats (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nic VARCHAR(17),
            last_updated VARCHAR(50),
            is_source TINYINT DEFAULT 0,
            tx_packet_count INT DEFAULT 0,
            rx_packet_count INT DEFAULT 0,
            sent_arp_count INT,
            FOREIGN KEY (nic)
                REFERENCES nic_record(mac_address) ON DELETE SET NULL
        )
        """,
        """
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
        """,
        """
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
            FOREIGN KEY (nic)
                REFERENCES nic_record(mac_address) ON DELETE SET NULL
        )
        """,
    ]

    execute_queries(cursor, tables)


def create_triggers(cursor):
    triggers = [
        """
        CREATE TRIGGER IF NOT EXISTS update_last_seen_trigger
            AFTER UPDATE ON nic_record
            FOR EACH ROW
            BEGIN
                UPDATE nic_stats
                SET last_updated = NEW.last_seen
                WHERE nic = NEW.mac_address;
            END;
        """,
        """
        CREATE TRIGGER IF NOT EXISTS insert_new_row_trigger
            AFTER INSERT ON nic_record
            FOR EACH ROW
            BEGIN
                INSERT INTO nic_stats (nic)
                VALUES (NEW.mac_address);
            END;
        """
    ]

    execute_queries(cursor, triggers)


def create_and_config_database():
    try:
        cursor, connection = connect_to_db(DB_CONFIG_1)
        create_database(cursor)
        create_tables(cursor)
        create_triggers(cursor)
        connection.commit()
    except mysql.Error as err:
        print(f"Error creating database or tables: {err}")
        sys.exit()
    finally:
        close_db_connection(cursor, connection)


def db_to_csv(cursor, connection):
    global OUTPUT_DIR
    global pause_capture_inserts

    # Step 1: Find the highest id number in csv_files
    cursor.execute("SELECT MAX(id) FROM csv_files")
    max_id_result = cursor.fetchone()
    next_id = 1 if max_id_result[0] is None else max_id_result[0] + 1

    # Define the CSV file name based on the next_id
    csv_file_name = f"{next_id}.csv"
    csv_file_path = os.path.join(OUTPUT_DIR, csv_file_name)

    # Step 2: Fetch the first and last timestamp from captured_packets
    cursor.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM captured_packets")
    timestamps = cursor.fetchone()

    start_datetime, end_datetime = timestamps if timestamps else (None, None)

    # Fetch data from captured_packets
    cursor.execute("SELECT * FROM captured_packets ORDER BY timestamp")
    result = cursor.fetchall()

    # Step 3: Write data to CSV
    headers = [i[0] for i in cursor.description]
    with open(csv_file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(result)

    # Step 4: Insert new row into csv_files
    if start_datetime and end_datetime:
        cursor.execute(
            """
            INSERT INTO csv_files (id, file_name, start_datetime, end_datetime)
            VALUES (%s, %s, %s, %s)
            """, (next_id, csv_file_name, start_datetime, end_datetime)
        )
        connection.commit()

    # Step 5: Truncate captured_packets
    cursor.execute("TRUNCATE TABLE captured_packets")
    connection.commit()

    pause_capture_inserts = False


def fetch_and_insert_database():
    global pause_capture_inserts

    while True:
        try:
            cursor, connection = connect_to_db(DB_CONFIG_4)
            cursor.execute(f"USE {DATABASE_NAME}")
        except mysql.Error as err:
            print(f"Error connecting to database: {err}")
            time.sleep(10)  # Retry after a short delay
            continue

        try:
            cursor.execute("SELECT COUNT(*) FROM captured_packets;")
            row_count = cursor.fetchone()[0]

            if row_count >= 5000:
                pause_capture_inserts = True
                db_to_csv(cursor, connection)
            else:
                pause_capture_inserts = False

            connection.commit()
        except mysql.Error as err:
            print(f"Error executing SQL query to count packets: {err}")

        try:
            time.sleep(60)  # Delay to prevent rapid polling

            if pending_nic_record:
                for nic in pending_nic_record:
                    try:
                        cursor.execute(
                            """
                            INSERT INTO nic_record (
                                mac_address,
                                last_updated
                            ) VALUES (%s, %s);
                            """,
                            (nic["mac_address"], nic["last_updated"])
                        )
                    except mysql.Error as err:
                        print(f"Error inserting NIC record: {err}")

                connection.commit()
                pending_nic_record.clear()  # Clear pending records after insertion

                try:
                    cursor.execute("SELECT mac_address FROM nic_record;")
                    mac_addresses = cursor.fetchall()
                    fetched_nic_record.clear()  # Clear the local copy before updating
                    if mac_addresses:
                        for mac_address in mac_addresses:
                            fetched_nic_record.append(mac_address[0])
                    connection.commit()
                except mysql.Error as err:
                    print(f"Error fetching NIC records: {err}")

        except mysql.Error as err:
            print(f"Error during NIC records operation: {err}")
        finally:
            close_db_connection(cursor, connection)
            time.sleep(10)


"""
  ____            _                  
 / ___|__ _ _ __ | |_ _   _ _ __ ___ 
| |   / _` | '_ \| __| | | | '__/ _ \
| |__| (_| | |_) | |_| |_| | | |  __/
 \____\__,_| .__/ \__|\__,_|_|  \___|
 ____      |_|   _   _               
/ ___|  ___  ___| |_(_) ___  _ __    
\___ \ / _ \/ __| __| |/ _ \| '_ \   
 ___) |  __/ (__| |_| | (_) | | | |  
|____/ \___|\___|\__|_|\___/|_| |_|

These functions are responsible for capturing and storing packets from
the network traffic. The capture_traffic function will capture network
traffic on the specified interface and store the packets in a pcap
file. The packet_to_db function will insert the packet data into the 
database captured_packets table. The determine_protocol function will
determine the protocol of the packet by extracting layer information
from the packet.

These functions will allow the network analyzer to capture network
traffic and store the packets in the database for further analysis.

"""

# ------------------------------------------------------ #
# Supporting functions for the capture_traffic function. #
# ------------------------------------------------------ #


def determine_protocol(packet):
    """
    Determine the protocol of the packet by
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


# ----------------------------------------------------------------- #
# Secondary function to insert packet data into the database table. #
# ----------------------------------------------------------------- #

def packet_to_db():
    """
    Function reads the packets from the pcap file and inserts the
    packet data into the database table captured_packets. The function
    will extract information such as source and destination IP
    addresses, MAC addresses, and protocols from the packets and INSERT
    this information into the database table captured_packets for
    further analysis. 

    This using several techniques to extract the information from the
    packets. One of the techniques is to use the Scapy library as it
    reads the packets. The other technique is to use the
    determine_protocol function to extract the protocol information
    from the packets.
    """
    global not_analyzed_count
    cursor, connection = connect_to_db(DB_CONFIG_1)

    if pending_pcap_files:
        packets = rdpcap(pending_pcap_files[0])
        pending_pcap_files.pop(0)

    try:
        for packet in packets:
            protocol_array = determine_protocol(packet)
            timestamp = datetime.fromtimestamp(float(packet.time))

            source_mac = packet[Ether].src if Ether in packet else None
            destination_mac = packet[Ether].dst if Ether in packet else None
            source_ip = packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else None
            destination_ip = packet[IP].dst if IP in packet else None
            source_port = packet.sport if TCP in packet else packet[
                UDP].sport if UDP in packet else None
            destination_port = packet.dport if TCP in packet else packet[
                UDP].dport if UDP in packet else None
            ethernet_type = str(protocol_array[0]).strip() if len(
                protocol_array) >= 1 else None
            network_protocol = str(protocol_array[1]).strip() if len(
                protocol_array) >= 2 else None
            transport_protocol = str(protocol_array[2]).strip() if len(
                protocol_array) >= 3 else None
            application_protocol = str(protocol_array[3]).strip() if len(
                protocol_array) >= 4 else None
            payload = bytes(packet[Raw].load) if Raw in packet else None

            insert_query = (
                f"""INSERT INTO {TABLE_NAME} (
                    timestamp, source_mac, destination_mac, source_ip,
                    destination_ip, source_port, destination_port,
                    ethernet_type, network_protocol, transport_protocol,
                    application_protocol, payload
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            )

            try:
                cursor.execute(f"USE {DATABASE_NAME}")
                cursor.execute(insert_query, (
                    timestamp, source_mac, destination_mac, source_ip,
                    destination_ip, source_port, destination_port,
                    ethernet_type, network_protocol, transport_protocol,
                    application_protocol, payload))
            except mysql.Error as err:
                print(f"Error inserting packet into database DETAILS: {err}")

        connection.commit()

    except Exception as e:
        print(f"Error extracting packet data: {e}")

    not_analyzed_count = fetch_count(
        cursor,
        "SELECT COUNT(*) FROM captured_packets WHERE analyzed = 0"
    )

    close_db_connection(cursor, connection)


# ----------------------------------------------- #
# Primary function that captures network traffic.
# ----------------------------------------------- #

def capture_traffic():
    """
    Capture network traffic on the specified interface and store the
    packets in a pcap file.
    """
    global pcap_filename
    global not_analyzed_count

    global pending_pcap_files

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

            sniff(
                iface=INTERFACE_NAME,
                prn=packet_pcap,
                timeout=TIMEOUT,
                stop_filter=lambda _: packet_count == PACKET_LIMIT
            )

            packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
            print(f"Capture in {time.time() - start_time} seconds.")
            print(f"Total packet count: {str(packet_count)} \n")

            pcap_filename = os.path.join(
                OUTPUT_DIR,
                f"{INTERFACE_NAME}-({packet_time_started})-({packet_time_ended}).pcap"
            )

            pending_pcap_files.append(pcap_filename)
            wrpcap(pcap_filename, captured_packets)

        except Exception as e:
            print(f"Error capturing traffic on {INTERFACE_NAME}: {e}")
        finally:
            if not pause_capture_inserts:
                packet_to_db()
            else:
                continue


"""
    _                _           _     
   / \   _ __   __ _| |_   _ ___(_)___ 
  / _ \ | '_ \ / _` | | | | / __| / __|
 / ___ \| | | | (_| | | |_| \__ \ \__ \
/_/   \_\_| |_|\__,_|_|\__, |___/_|___/
 ____            _   _ |___/           
/ ___|  ___  ___| |_(_) ___  _ __      
\___ \ / _ \/ __| __| |/ _ \| '_ \     
 ___) |  __/ (__| |_| | (_) | | | |    
|____/ \___|\___|\__|_|\___/|_| |_|

This is the packet analysis functions that are responsible for
analyzing the packets captured by the capture_traffic function.
The packet analysis functions will analyze the packets and extract
information such as source and destination IP addresses, MAC
addresses, and protocols. The packet analysis functions will then
store this information in the database for further analysis.

This analysis process allows the network analyzer and eventually
PyTorch to analyze the network traffic and detect any anomalies or
suspicious activity in the network. It takes a lot of key data points
out from the packets and allows for the building of the statistical
models to detect any changes in behavior or patterns in every single
NIC and IP address in the network.

"""

# ---------------------------------------------------------------- #
# Supporting functions to analyze NIC and IP addresses information #
# ---------------------------------------------------------------- #


def is_nic_new(mac_address):
    if mac_address not in local_nic_record or pending_nic_record:
        return True
    return False


def has_ip_changed(mac_address, ip_address, cursor):
    return fetch_and_compare(
        cursor,
        ip_address,
        "SELECT last_known_ip FROM nic_record WHERE mac_address = %s;",
        (mac_address,)
    )


def is_ip_new(ip_address, cursor):
    return fetch_primary_key(
        cursor,
        f"SELECT * FROM ip_addresses WHERE ip_address = '{ip_address}';"
    )


def check_for_vpn(protocol):
    # Check if the packet contains a VPN protocol
    return protocol in VPN_PROTOCOLS


# -------------------------------------------- #
# Secondary functions in the analysis process. #
# -------------------------------------------- #

def analyze_packet():
    """
    Analyzes each packet and sets flags for things like VPN detection,
    ARP detection, etc. This function will be inserting and
    updating the analyzed_packets table which will contain a one-to-
    one relationship with the captured_packets table. This will allow
    for easy tracking of the packets that have been analyzed and
    flagged for further analysis.
    """
    # Placeholder for packet analysis
    pass


def analyze_nic(mac_address, timestamp, cursor):
    """
    Analyze the NIC and retrieve relevant data points.

    The use of 'if mac_address' is to ensure that the MAC address is
    not empty or None. This is to prevent any errors that may occur
    specifically with ARP packets which do not contain a source MAC
    """
    if mac_address:
        try:
            """
            If NIC is new, insert into nic_record and nic_stats.
            The is_nic_new function will return True if the NIC is new
            """
            if is_nic_new(mac_address):
                pending_nic_record.append(
                    {
                        "mac_address": mac_address,
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                    }
                )
            else:
                """
                If NIC is not new to the nic_record table, update the
                last_seen and last_updated timestamps in their
                respective tables. 
                """
                local_nic_record[mac_address]["last_updated"] = timestamp

        except mysql.Error as err:
            print(f"Error: {err}")


def analyze_ip(mac_address, ip_address, timestamp, cursor):
    """
    Analyze the IP address and retrieve relevant data points.

    The use of 'if ip_address' is to ensure that the IP address is not
    empty or None. This is to prevent any errors that may occur
    specifically with ARP request packets which do not contain an 
    destination IP address.
    """
    if ip_address:
        try:
            # Check if the IP address is new to the ip_addresses table
            if is_ip_new(ip_address, cursor):
                is_ipv6 = 1 if ":" in ip_address else 0
                cursor.execute(
                    """
                    INSERT INTO ip_addresses (
                        ip_address,
                        is_ipv6,
                        first_seen
                    ) VALUES (%s, %s, %s);
                    """,
                    (ip_address, is_ipv6, timestamp)
                )
                cursor.execute(
                    """
                    UPDATE nic_record
                        SET last_known_ip = %s
                        WHERE mac_address = %s;
                    """,
                    (ip_address, mac_address)
                )
                cursor.execute(
                    """
                    INSERT INTO nic_previous_ips (
                        mac_address,
                        ip_address,
                        first_seen,
                        last_seen
                    ) VALUES (%s, %s, %s, %s);
                    """,
                    (mac_address, ip_address, timestamp, timestamp)
                )

                if has_ip_changed(mac_address, ip_address, cursor):
                    cursor.execute(
                        """
                        UPDATE nic_record
                            SET last_known_ip = %s
                            WHERE mac_address = %s;
                        """,
                        (ip_address, mac_address)
                    )
                    cursor.execute(
                        """
                        UPDATE ip_addresses
                            SET last_seen = %s
                            WHERE ip_address = %s;
                        """,
                        (timestamp, ip_address)
                    )
                    cursor.execute(
                        """
                        INSERT INTO nic_previous_ips (
                            mac_address,
                            ip_address,
                            first_seen,
                            last_seen
                        ) VALUES (%s, %s, %s, %s);
                        """,
                        (mac_address, ip_address, timestamp, timestamp)
                    )

        except mysql.Error as err:
            print(f"Error: {err}")
        finally:
            cursor.execute(
                """
                UPDATE ip_addresses
                    SET last_seen = %s
                    WHERE ip_address = %s;
                """,
                (timestamp, ip_address)
            )
            cursor.execute(
                """
                UPDATE nic_previous_ips
                    SET last_seen = %s
                    WHERE mac_address = %s
                    AND ip_address = %s;
                """,
                (timestamp, mac_address, ip_address)
            )

# ------------------------------------------------- #
# This is the primary function to analyze the packets
# ------------------------------------------------- #


def packet_analysis():
    while True:
        try:
            cursor, connection = connect_to_db(DB_CONFIG_2)
            cursor.execute(f"USE {DATABASE_NAME}")
            time.sleep(2)
            print("Fetching all unanalyzed packets")
            cursor.execute(
                """
                SELECT * FROM captured_packets WHERE analyzed = 0 ORDER BY id LIMIT 1000;
                """
            )
            packets = cursor.fetchall()

            if packets:
                print(f"Analyzing {len(packets)} packets...")

                for packet in packets:
                    """
                    Variables used for clarity and troubleshooting

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
                    """

                    analyze_packet()  # Placeholder for future use

                    analyze_nic(packet[2], packet[1], cursor)
                    analyze_nic(packet[3], packet[1], cursor)
                    # analyze_ip(packet[2], packet[4], packet[1], cursor)
                    # analyze_ip(packet[3], packet[5], packet[1], cursor)

                    cursor.execute(
                        """
                        UPDATE nic_stats
                            SET tx_packet_count = tx_packet_count + 1
                            WHERE nic = %s;
                        """,
                        (packet[2],)
                    )

                    # If statement is used to prevent
                    # errors with ARP packets
                    if packet[3]:
                        cursor.execute(
                            """
                            UPDATE nic_stats
                                SET rx_packet_count = rx_packet_count + 1
                                WHERE nic = %s;
                            """,
                            (packet[3],)
                        )

                    cursor.execute(
                        """
                        UPDATE captured_packets
                            SET analyzed = 1
                            WHERE id = %s;
                        """,
                        (packet[0],)
                    )

                connection.commit()
                print("Analysis complete.")

        except mysql.Error as err:
            print(f"Error: {err}")
        finally:
            close_db_connection(cursor, connection)


"""
 ____                 _ _            
| __ )  __ _ ___  ___| (_)_ __   ___ 
|  _ \ / _` / __|/ _ \ | | '_ \ / _ \
| |_) | (_| \__ \  __/ | | | | |  __/
|____/ \__,_|___/\___|_|_|_| |_|\___|                                    
 ____            _   _               
/ ___|  ___  ___| |_(_) ___  _ __    
\___ \ / _ \/ __| __| |/ _ \| '_ \   
 ___) |  __/ (__| |_| | (_) | | | |  
|____/ \___|\___|\__|_|\___/|_| |_| 

The baseline analysis function is responsible for analyzing the
nic_stats, ip_address_stats, and network_stats tables to determine
if any changes have occurred in key data points. If changes are
detected, the function will update the baselines table with the
new data points.

These baselines will be used as a "snapshot" for each NIC. There
will be a baseline for each NIC for each time period (daily, weekly,
monthly, etc.). These baselines will be used to compare the current
data points with the baseline data points to determine if any
significant changes have occurred. If changes are detected, ideally
an alert will be generated to notify the user of the change in be-
havior.
                                                                        
"""

# ------------------------------------------------ #
# Secondary functions to assist baseline_analysis. #
# ------------------------------------------------ #


def has_packet_count_changed(mac_address, total_packet_count, cursor):
    return fetch_and_compare(
        cursor, total_packet_count,
        """
        SELECT total_packet_count FROM nic_record WHERE mac_address = %s;
        """,
        (mac_address,)
    )


def has_packet_rate_changed(mac_address, packet_rate, cursor):
    # future use
    pass


def has_packet_size_changed(mac_address, packet_size, cursor):
    # future use
    pass


def has_peak_packet_rate_changed(mac_address, peak_packet_rate, cursor):
    # future use
    pass


def has_peak_bandwidth_changed(mac_address, peak_bandwidth, cursor):
    # future use
    pass


def has_most_common_protocol_changed(mac_address, protocol, cursor):
    # future use
    pass


def has_most_common_source_ip_changed(mac_address, source_ip, cursor):
    # future use
    pass


def has_most_common_dst_ip_changed(mac_address, destination_ip, cursor):
    # future use
    pass


def has_top_five_dst_nic_changed(mac_address, packet_error_rate, cursor):
    # future use
    pass

# ----------------------------------------------------------------- #
# Primary function that builds and modifies baselines on stat data. #
# ----------------------------------------------------------------- #


def baseline_analysis():
    """
    By analyzing the NIC and IP address statistics, the baseline
    analysis function will determine if any changes have occurred in
    the data points. If changes are detected, the function will update
    the baselines table with the new data points.

    The baseline analysis function will run on a separate thread and
    will be executed every 30 seconds. This will allow the function to
    continuously monitor the statistics and update the baselines as
    needed.
    """
    while True:
        cursor, connection = connect_to_db(DB_CONFIG_3)
        cursor.execute(f"USE {DATABASE_NAME}")
        try:
            # Ensures the server does not get overloaded with requests
            time.sleep(30)

            cursor.execute("""
                SELECT baseline_type FROM baselines
                    WHERE finalized = 0 AND baseline_type = 'daily';
                """
                           )
            rows = cursor.fetchall()
            if rows is not None:
                for row in rows:
                    nic = row[1]
            else:
                continue  # if None, continue to next iteration

            connection.commit()
        except mysql.Error as err:
            print(f"Error executing SQL query 4: {err}")
        finally:
            close_db_connection(cursor, connection)


"""
 __  __       _         _____                 _   _             
|  \/  | __ _(_)_ __   |  ___|   _ _ __   ___| |_(_) ___  _ __  
| |\/| |/ _` | | '_ \  | |_ | | | | '_ \ / __| __| |/ _ \| '_ \ 
| |  | | (_| | | | | | |  _|| |_| | | | | (__| |_| | (_) | | | |
|_|  |_|\__,_|_|_| |_| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|

This is the main function that will be executed when the program is
run. The main function will create the database and tables, and then
start the capture_traffic, packet_analysis, and baseline_analysis
functions in separate threads.

The threads will run continuously until the program is stopped. The
capture_traffic function will capture network traffic and store the
packets in a pcap file. The packet_analysis function will analyze the
packets and store the results in the database. The baseline_analysis
function will analyze the NIC and IP address statistics and update
the baselines as needed.

Creating the threads and starting them will allow the program to
continuously monitor the network traffic in almost real-time and
analyze the packets to detect any changes in behavior which is
important for network security and monitoring.
"""


def main():
    create_and_config_database()

    fetch_insert_thread = threading.Thread(target=fetch_and_insert_database)
    capture_thread = threading.Thread(target=capture_traffic)
    analysis_thread = threading.Thread(target=packet_analysis)
    baseline_thread = threading.Thread(target=baseline_analysis)

    fetch_insert_thread.start()
    capture_thread.start()
    analysis_thread.start()
    baseline_thread.start()

    fetch_insert_thread.join()
    capture_thread.join()
    analysis_thread.join()
    baseline_thread.join()


if __name__ == '__main__':
    main()
