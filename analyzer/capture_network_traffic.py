import os,sys, time, subprocess
from scan_network_traffic import begin_scan

from datetime import datetime

import mysql.connector as mysql
from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, Raw
from scapy.arch.windows import get_windows_if_list

# Constants
PACKET_LIMIT = 100000
TIMEOUT = 600 # 10 minutes
OUTPUT_DIR = "pcap_files"

os.makedirs(OUTPUT_DIR, exist_ok=True)

#Array 
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


def truncate_table(cursor, tb_name):
    cursor.execute(f"TRUNCATE TABLE {tb_name};")


def create_database_and_table(cursor, db_name, tb_name):
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")

    if input(f'Do you want to clear {tb_name} table? Type "clear" or press Enter): ') == "clear":
        truncate_table(cursor, tb_name)
    else:
        cursor.execute(f"USE {db_name}")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_packets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME NOT NULL,
            source_mac VARCHAR(17),
            source_ip VARCHAR(45),
            destination_ip VARCHAR(45),
            source_port INT,
            destination_port INT,
            protocol VARCHAR(10),
            payload BLOB,
            processed TINYINT DEFAULT 0,
            is_vpn TINYINT DEFAULT 0
        );
        """)


def packet_to_db(packet, db_config):
    insert_query = """
    INSERT INTO raw_packets (timestamp, source_mac, source_ip, destination_ip, source_port, destination_port, protocol, payload)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    # Extract necessary fields from the packet
    source_mac = packet[Ether].src if Ether in packet else None
    timestamp = datetime.now()
    source_ip = packet[IP].src if IP in packet else None
    destination_ip = packet[IP].dst if IP in packet else None
    source_port = packet.sport if TCP in packet or UDP in packet else None
    destination_port = packet.dport if TCP in packet or UDP in packet else None
    protocol = packet.sprintf("%IP.proto%") if IP in packet else None
    payload = bytes(packet[Raw].load) if Raw in packet else None

    connection = mysql.connect(**db_config)
    cursor = connection.cursor()
    cursor.execute(insert_query, (timestamp, source_mac, source_ip, destination_ip, source_port, destination_port, protocol, payload))
    connection.commit()
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

        cursor.execute(f"USE {database_name}")
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        print_divider(80, 1)
        print("All avaliable tables:")

        for (table_name,) in tables:
            print(table_name)

        print_divider(0,1)
        table_name = input("Enter table name you need to create or use: ")

        create_database_and_table(cursor, database_name, table_name)
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

    #Start the scanning packet process by opening py file
    begin_scan(database_name, table_name)
    sys.exit()

if __name__ == "__main__":
    main()