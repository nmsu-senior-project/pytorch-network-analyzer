import sys
from datetime import datetime

import mysql.connector as mysql

# Constants
common_vpn_protocols = ["OpenVPN", "IKEv2", "L2P2", "PPTP", "WireGuard", "SSTP"]


def read_credentials(filename, start_line, end_line):
    credentials = {}
    with open(filename, 'r') as file:
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
    for protocol in common_vpn_protocols:
        if protocol == str(payload):
            return True, protocol
    return False, None


def begin_scan(db_name, tb_name):
    # Connect to database
    try:
        mysqlcon = mysql.connect(user=db_user,
                                password=db_pass,
                                host='localhost',
                                port=3306,
                                database=db_name)
        mysqlcon.autocommit = True
    except mysql.Error as err:
        print(f"Error: {err}")
        sys.exit()

    packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")

    while True:
        # Fetch the first unprocessed packet
        cursor = mysqlcon.cursor()
        cursor.execute(f"USE {str(db_name)}")
        cursor.execute(f"SELECT * FROM {str(tb_name)} WHERE processed = 0 ORDER BY id;")
        raw_packets = cursor.fetchall()

        if raw_packets:
            for packet in raw_packets:
                packet_id = packet[0]
                protocol = packet[7]

                print(packet)
                cursor.execute(f"UPDATE {tb_name} SET processed = 1 WHERE id = {packet[0]};")
                print(f"Processing packet ID: {packet_id}")

                # Check for VPN protocols
                vpn_detected, protocol = check_for_vpn(protocol)
                if vpn_detected:
                    print(f"VPN protocol detected: {protocol}")
                    # Update the 'is_vpn' column in the database
                    cursor.execute(f"UPDATE {tb_name} SET is_vpn = 1 WHERE id = {packet_id};")
                    mysqlcon.commit()
                    print(f"Packet ID {packet_id} marked as VPN in the database.")

                    packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")

            packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
            print("Started scanning at " + packet_time_started)
            print("Ended scanning at " + packet_time_ended)
        else:
            print("No unprocessed packets found.")
            break

        # if raw_packet:
        #     packet_id = raw_packet[0]
        #     payload = raw_packet[1]
        #     print(f"Processing packet ID: {packet_id}")

        #     # Check for VPN protocols
        #     vpn_detected, protocol = check_for_vpn(payload)
        #     if vpn_detected:
        #         print(f"VPN protocol detected: {protocol}")
        #         # Update the 'is_vpn' column in the database
        #         cursor.execute(f"UPDATE {tb_name} SET is_vpn = 1 WHERE id = {packet_id};")
        #         mysqlcon.commit()
        #         print(f"Packet ID {packet_id} marked as VPN in the database.")

        #         packet_time_started = datetime.now().strftime("%Y-%m-%d_%H-%M")

        # packet_time_ended = datetime.now().strftime("%Y-%m-%d_%H-%M")
        # print("Ended scanning at " + packet_time_ended)


# if __name__ == "__main__":
#     main()