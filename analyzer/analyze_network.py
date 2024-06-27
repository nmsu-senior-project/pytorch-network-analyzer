import os, sys
from datetime import datetime

import mysql.connector as mysql

from setup_network import INTERFACE_NAME, DB_CONFIG, DATABASE_NAME, TABLE_NAME
from capture_network import pcap_filename

# Constants
VPN_PROTOCOLS = ["OpenVPN", "IKEv2", "L2P2", "PPTP", "WireGuard", "SSTP"]


def connect_to_db(db_config):
    connection = mysql.connect(**db_config)
    cursor = connection.cursor()

    return cursor, connection


def read_credentials(start_line, end_line):
    credentials = {}
    # Construct an absolute path to the file
    script_dir = os.path.dirname(__file__)  # Directory of the script
    filepath = os.path.join(script_dir, pcap_filename)  # Path to the file

    with open(filepath, 'r') as file:
        # Skip lines before the starting line
        for _ in range(start_line - 1):
            file.readline()

        # Read and process lines within the specified range
        for line_number in range(start_line, end_line + 1):
            line = file.readline().strip()
            if line:  # Check if line is not empty
                key, value = line.split(':')
                credentials[key.strip()] = value.strip()

    return credentials


# Credential collection
credentials = read_credentials('credentials.txt', 3, 4)
db_user = credentials.get('db_user')
db_pass = credentials.get('db_pass')


def check_for_vpn(payload):
    """Check if any of the common VPN protocols are present in the payload."""
    for protocol in VPN_PROTOCOLS:
        if protocol == str(payload):
            return True, protocol
    return False, None


async def begin_analysis():
    # Connect to database
    try:
        cursor, connection = connect_to_db(DB_CONFIG)
    except mysql.Error as err:
        print(f"Error: {err}")
        sys.exit()

    packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")

    while True:
        # Fetch the first unprocessed packet
        cursor = connection.cursor()
        cursor.execute(f"USE {str(DATABASE_NAME)}")
        cursor.execute(f"SELECT * FROM captured_packets WHERE analyzed = 0 ORDER BY id;")
        captured_packets = cursor.fetchall()

        try:
            if captured_packets:
                for packet in captured_packets:
                    packet_id = packet[0]
                    protocol = packet[7]

                    print(packet)
                    cursor.execute(f"UPDATE {TABLE_NAME} SET analyzed = 1 WHERE id = {packet[0]};")
                    print(f"Processing packet ID: {packet_id}")

                    # Check for VPN protocols
                    vpn_detected, protocol = check_for_vpn(protocol)
                    if vpn_detected:
                        print(f"VPN protocol detected: {protocol}")
                        # Update the 'is_vpn' column in the database
                        cursor.execute(f"UPDATE {TABLE_NAME} SET is_vpn = 1 WHERE id = {packet_id};")
                        connection.commit()
                        print(f"Packet ID {packet_id} marked as VPN in the database.")

                        packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")

                packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
                print("Started scanning at " + packet_time_started)
                print("Ended scanning at " + packet_time_ended)
            else:
                print("No unprocessed packets found.")
                break
        except mysql.Error as err:
            print(f"Error: {err}")
            sys.exit()
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()