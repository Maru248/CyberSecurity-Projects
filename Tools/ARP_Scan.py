import argparse
import csv
import sys
import ipaddress
from scapy.all import ARP, Ether, srp

def validate_ip_range(ip_range: str) -> str:
    """Validate IP range in CIDR format."""
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        return str(network)
    except ValueError:
        sys.exit("Invalid IP range. Please use CIDR notation (e.g., 192.168.1.0/24).")

def scan(target_ip):
    print(f"Scanning {target_ip}...")

    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, timeout=3, verbose=0)[0]
    except PermissionError:
        sys.exit("Error: You must run this script with root/admin privileges.")

    clients = []
    for _, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    clients.sort(key=lambda x: x['ip'])
    return clients

def display_results(clients):
    if clients:
        print("\nAvailable devices in the network:")
        print("IP" + " " * 18 + "MAC")
        for client in clients:
            print("{:16}{}".format(client['ip'], client['mac']))
    else:
        print("No devices found. Make sure you're connected to the network.")

def export_to_csv(clients, filename):
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['ip', 'mac'])
        writer.writeheader()
        writer.writerows(clients)
    print(f"\nResults saved to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Network Scanner")
    parser.add_argument("-t", "--target", help="Target IP range (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", help="CSV file to export results")
    args = parser.parse_args()

    # Fallback to prompt if no target is provided
    ip_range = args.target or input("Enter IP range to scan (e.g., 192.168.1.0/24): ")
    validated_target = validate_ip_range(ip_range)

    clients = scan(validated_target)
    display_results(clients)

    if args.output:
        export_to_csv(clients, args.output)
