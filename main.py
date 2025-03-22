import socket
import requests
import sys
import random
import time
from tqdm import tqdm
from scapy.all import *

# Define service names for known ports for better readability
def get_port_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown Service"

# Detect IP version (IPv4 or IPv6)
def detect_ip_version(ip_address):
    try:
        socket.inet_pton(socket.AF_INET, ip_address)
        return 4
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip_address)
            return 6
        except socket.error:
            raise ValueError("Invalid IP address format.")

# Create packet for TCP Connect, SYN, and ACK scans based on IP version
def create_packet(ip_version, target_ip, port, flags):
    if ip_version == 4:
        return IP(dst=target_ip) / TCP(dport=port, flags=flags)
    elif ip_version == 6:
        return IPv6(dst=target_ip) / TCP(dport=port, flags=flags)

# Advanced port scan with multiple methods and increased precision
def advanced_port_scan(target_ip, start_port, end_port, ip_version=4, retries=3, timeout=3):
    open_ports = []
    closed_ports = []
    filtered_ports = []
    total_ports = end_port - start_port + 1
    print(f"Initiating advanced scan on {target_ip} from ports {start_port} to {end_port}...")

    with tqdm(total=total_ports, desc="Scanning Ports", unit="port") as pbar:
        for port in range(start_port, end_port + 1):
            port_state = "Filtered"
            detected_service = get_port_name(port)

            # Try TCP Connect, SYN, and ACK scan to maximize accuracy
            for attempt in range(retries):
                # TCP Connect (complete handshake) - Detect open/closed
                try:
                    sock = socket.socket(socket.AF_INET6 if ip_version == 6 else socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target_ip, port))
                    if result == 0:  # Connection successful, port is open
                        port_state = "Open"
                        open_ports.append(port)
                        sock.close()
                        break
                    else:
                        closed_ports.append(port)
                        port_state = "Closed"
                    sock.close()
                except:
                    pass

                # SYN Scan for stealth - Detect open/closed without completing the handshake
                pkt = create_packet(ip_version, target_ip, port, 'S')
                resp = sr1(pkt, timeout=timeout, verbose=0)
                if resp:
                    if resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        port_state = "Open"
                        open_ports.append(port)
                        break
                    elif resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x14:  # RST
                        closed_ports.append(port)
                        port_state = "Closed"
                    elif resp.haslayer(ICMP):
                        filtered_ports.append(port)
                        port_state = "Filtered"
                else:
                    port_state = "Filtered"

                # ACK scan - Used to check firewall presence
                pkt = create_packet(ip_version, target_ip, port, 'A')
                resp = sr1(pkt, timeout=timeout, verbose=0)
                if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x4:  # RST
                    port_state = "Unfiltered" if port_state == "Filtered" else port_state

            # Display port status in real-time on the same line
            sys.stdout.write(f"\rScanning Port {port} ({detected_service}): {port_state}   ")
            sys.stdout.flush()
            pbar.update(1)

    # Move to the next line after the scan completes
    sys.stdout.write("\n")
    print("Scan completed.")
    return open_ports

# Service/Version Detection
def version_detection(target_ip, open_ports, ip_version=4, timeout=3):
    print("\nAttempting service/version detection on open ports...")
    with tqdm(total=len(open_ports), desc="Service Detection", unit="port") as pbar:
        for port in open_ports:
            try:
                # Try grabbing banners by making a simple connection
                sock = socket.socket(socket.AF_INET6 if ip_version == 6 else socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((target_ip, port))
                sock.send(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                response = sock.recv(1024)
                sock.close()
                tqdm.write(f"Port {port}: {response.decode('utf-8').strip()}")
            except Exception as e:
                tqdm.write(f"Port {port}: Unable to retrieve service/version details. {e}")
            pbar.update(1)

# Main function
def main():
    target_ip = input("Enter target IP: ")
    try:
        ip_version = detect_ip_version(target_ip)
        print(f"Detected IP version: IPv{ip_version}")
    except ValueError as e:
        print(e)
        return

    start_port = int(input("Enter starting port: "))
    end_port = int(input("Enter ending port: "))

    # Perform advanced port scan
    open_ports = advanced_port_scan(target_ip, start_port, end_port, ip_version)

    # Perform version detection on open ports
    if open_ports:
        version_detection(target_ip, open_ports, ip_version)
    else:
        print("No open ports detected in the specified range.")

if __name__ == "__main__":
    main()
