import asyncio
import os
import sys
import mysql.connector as mysql

# Constants
CREDENTIALS_FILENAME = 'credentials.txt'
CREDENTIALS_LOCATION = os.path.join(os.getcwd(), CREDENTIALS_FILENAME)
DATABASE_NAME = "network"
TABLE_NAME = "captured_packets"
INTERFACE_NAME = "Wi-Fi"
DB_CONFIG = {
    'user': None,  # Placeholder for actual value from credentials
    'password': None,  # Placeholder for actual value from credentials
    'host': 'localhost',
    'port': 3306,
    # 'auth_plugin': 'mysql_native_password'  # Specify the authentication plugin here if needed
}


def create_database_and_tables(cursor):
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
                timestamp DATETIME,
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
            CREATE TABLE IF NOT EXISTS NIC_record (
                mac_address VARCHAR(17) PRIMARY KEY,
                manufacturer VARCHAR(255),
                ip_addresses VARCHAR(45),
                first_seen DATETIME,
                last_seen DATETIME,
                last_known_location VARCHAR(255),
                previous_locations VARCHAR(255),
                FOREIGN KEY (ip_addresses) REFERENCES ip_addresses(ip_address) ON DELETE SET NULL
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
                FOREIGN KEY (source_NIC) REFERENCES NIC_record(mac_address) ON DELETE CASCADE,
                FOREIGN KEY (destination_NIC) REFERENCES NIC_record(mac_address) ON DELETE CASCADE
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
                FOREIGN KEY (associated_NIC) REFERENCES NIC_record(mac_address) On DELETE SET NULL
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
                FOREIGN KEY (nic_mac_address) REFERENCES NIC_record(mac_address) ON DELETE SET NULL
            )
        """)

    except mysql.Error as err:
        print(f"Error creating database or tables: {err}")
        sys.exit()


def read_specific_lines(filename, line_numbers):
    credentials = {}
    # Construct an absolute path to the file
    script_dir = os.path.dirname(__file__)  # Directory of the script
    filepath = os.path.join(script_dir, filename)  # Path to the file

    try:
        with open(filepath, 'r') as file:
            lines = file.readlines()
            for line_number in line_numbers:
                if line_number <= 0 or line_number > len(lines):
                    print(f"Invalid line number: {line_number}")
                    return None
                line = lines[line_number - 1].strip()
                if line:
                    key, value = line.split(':')
                    credentials[key.strip()] = value.strip()
    except FileNotFoundError:
        print(f"The file {filepath} was not found.")
        return None
    if not credentials:
        print(f"No valid lines found for numbers: {line_numbers}")
        return None
    return credentials


def connection_and_creation():
    connection = None
    cursor = None

    try:
        credentials = read_specific_lines('credentials.txt', [1, 2])

        if credentials:
            db_user = credentials.get('db_user')
            db_pass = credentials.get('db_pass')
            DB_CONFIG['user'] = db_user
            DB_CONFIG['password'] = db_pass
        else:
            print("Failed to read credentials.")
            sys.exit()

        connection = mysql.connect(**DB_CONFIG)
        cursor = connection.cursor()

        create_database_and_tables(cursor)

    except mysql.Error as err:
        print(f"MySQL error: {err}")
        sys.exit()

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


async def main():
    # Initialize your connection and setup tasks here if needed
    connection_and_creation()

    capture_command = ['python', 'capture_network.py']
    analysis_command = ['python', 'analyze_network.py']

    capture_process = await asyncio.create_subprocess_exec(*capture_command)
    await capture_process.wait()

    analysis_process = await asyncio.create_subprocess_exec(*analysis_command)
    await analysis_process.wait()

    # Any additional asyncio tasks can be added here

if __name__ == '__main__':
    asyncio.run(main())