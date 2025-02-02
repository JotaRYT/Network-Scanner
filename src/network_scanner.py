#!/usr/bin/env python3

"""
Network Scanner Tool
This script performs network scanning and port scanning on discovered devices.
"""

# Import the required modules
import socket
from typing import List, Dict
from scapy.all import ARP, Ether, srp

# Define the functions
def scan_network(ip_range: str) -> List[Dict[str, str]]:
    """
    Scan the network for active devices using ARP requests.
    
    Args:
        ip_range (str): Network range to scan (e.g., "192.168.1.0/24")
    
    Returns:
        List[Dict[str, str]]: List of dictionaries containing IP and MAC addresses
    """
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        hostname = get_hostname(received.psrc)
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': hostname
        })

    # Return the list of devices
    return devices

# Define the function to scan ports
def scan_ports(ip: str, ports: List[int]) -> List[int]:
    """
    Scan specified ports on a given IP address.
    
    Args:
        ip (str): IP address to scan
        ports (List[int]): List of port numbers to scan
    
    Returns:
        List[int]: List of open ports
    """
    open_ports = []
    
    # Scan each port in the list
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except socket.error:
            continue
    # Return the list of open ports
    return open_ports

# Define the function to get device's name
def get_hostname(ip: str) -> str:
    """
    Get hostname for an IP address using reverse DNS lookup.
    
    Args:
        ip (str): IP address to lookup
    
    Returns:
        str: Hostname if found, otherwise original IP
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return "Unknown"
    
# Define the main function
def main():
    """Main function to run the network scanner."""
    # Configuration
    IP_RANGE = "192.168.1.0/24"  # Change this to your network range
    PORTS_TO_SCAN = [
        21,   # FTP
        22,   # SSH
        23,   # Telnet
        80,   # HTTP
        443,  # HTTPS
        3389  # RDP
    ]

    # Print the header
    print(f"Scanning network range: {IP_RANGE}")
    
    # Scan the network for devices
    devices = scan_network(IP_RANGE)
    
    # Check if devices were found
    if not devices:
        print("No devices found.")
        return

    # Scan each device for open ports
    for device in devices:
        print(f"\nDevice found:")
        print(f"IP: {device['ip']}")
        print(f"MAC: {device['mac']}")
        print(f"Hostname: {device['hostname']}")
        
        open_ports = scan_ports(device['ip'], PORTS_TO_SCAN)
        if open_ports:
            print(f"Open ports: {open_ports}")
        else:
            print("No open ports found")

# Run the main function
if __name__ == "__main__":
    main()