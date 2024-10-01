import logging
from scapy.all import sniff, IP
import pandas as pd
import plotly.express as px
from collections import Counter
import time

# Set up logging
logging.basicConfig(filename='network_traffic_analysis.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# List of known malicious IPs (replace these with real malicious IP addresses if available)
MALICIOUS_IPS = ['192.168.1.100', '10.0.0.5', '34.80.249.38','8.142.19.29','152.89.198.155','103.102.230.5','161.35.216.181','45.45.237.33','125.124.117.195','108.21.107.119','35.229.223.132','39.109.112.75','13.233.244.165','34.81.173.225','45.148.10.240','142.181.46.243','49.65.1.179','217.76.58.114','121.66.58.157','98.113.203.148','14.56.193.140','34.80.211.11']

# Function to process each packet and check for potential threats
def process_packet(packet_list, packet):
    try:
        if packet.haslayer(IP):  # Check if the packet has an IP layer
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            packet_list.append(packet)

            # Check if the source IP is in the malicious IP list
            if ip_src in MALICIOUS_IPS:
                print(f"[THREAT] Detected packet from malicious IP: {ip_src}")
                logging.warning(f"Threat detected from malicious IP: {ip_src}")

            # Log each captured packet (can be disabled for performance)
            logging.info(f"New packet captured: {ip_src} -> {ip_dst}")
            print(f"New packet: {ip_src} -> {ip_dst}")
    except Exception as e:
        logging.error(f"An error occurred while processing the packet: {e}")
        print(f"[ERROR] An error occurred while processing the packet: {e}")

# Function to sniff packets for a set duration
def sniff_packets(interface, duration=30):
    packets = []
    try:
        print(f"Sniffing packets on interface {interface} for {duration} seconds...")
        logging.info(f"Started sniffing packets on interface {interface} for {duration} seconds")
        sniff(iface=interface, prn=lambda pkt: process_packet(packets, pkt), timeout=duration)
    except Exception as e:
        logging.error(f"Failed to sniff packets: {e}")
        print(f"[ERROR] Failed to sniff packets: {e}")
    return packets

# Function to detect high traffic from individual IP addresses
def detect_high_traffic(ip_counts, threshold=20):
    for ip, count in ip_counts.items():
        if count > threshold:
            print(f"[THREAT] {ip} is generating an unusually high amount of traffic ({count} packets)")
            logging.warning(f"Potential DDoS detected: {ip} sent {count} packets")

# Function to visualize the network traffic using Plotly and Pandas
def visualize_traffic(ip_counts):
    try:
        # Convert the IP counts to a pandas DataFrame for easier manipulation
        df = pd.DataFrame(ip_counts.items(), columns=['Source IP', 'Packet Count'])

        # Generate the bar chart using Plotly
        fig = px.bar(df, x='Source IP', y='Packet Count',
                     labels={'x': 'Source IP', 'y': 'Packet Count'},
                     title='Packet Counts per Source IP')

        fig.show()
        logging.info("Traffic visualization generated successfully")
    except Exception as e:
        logging.error(f"Failed to create visualization: {e}")
        print(f"[ERROR] Failed to create visualization: {e}")

# Main function to run the network traffic analysis tool
def main():
    logging.info("Network Traffic Analysis Tool started")
    
    # Ask the user to specify the network interface (e.g., eth0, wlan0)
    interface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ")
    
    # Step 1: Sniff network packets (for a specified duration)
    packets = sniff_packets(interface=interface, duration=90)

    # Step 2: Analyze the source IPs
    src_ips = [pkt[IP].src for pkt in packets if pkt.haslayer(IP)]
    ip_counts = Counter(src_ips)

    # Step 3: Detect high traffic (potential DDoS or scanning activity)
    detect_high_traffic(ip_counts, threshold=20)

    # Step 4: Ask the user if they want to visualize the traffic
    visualize = input("Do you want to visualize the captured traffic? (y/n): ").strip().lower()
    if visualize == 'y':
        visualize_traffic(ip_counts)

    logging.info("Network Traffic Analysis Tool finished execution")

# Entry point of the script
if __name__ == "__main__":
    main()

