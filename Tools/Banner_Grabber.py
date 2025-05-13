import socket
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

def banner_grab(ip, port, timeout=3):
    """Connects to the target and attempts to grab a service banner."""
    try:
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                banner = s.recv(1024).decode(errors="ignore").strip()
                return (ip, port, banner if banner else "No banner received.")
            except socket.timeout:
                return (ip, port, "Connected, but no banner received (timeout).")
    except Exception as e:
        return (ip, port, f"Error: {e}")

def scan_targets(ip, ports, threads=10):
    """Scans multiple ports in parallel using threads."""
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(banner_grab, ip, port): port for port in ports}
        for future in as_completed(future_to_port):
            results.append(future.result())
    return results

def export_to_csv(results, filename):
    """Saves scan results to a CSV file."""
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP', 'Port', 'Banner'])
        writer.writerows(results)
    print(f"\nResults saved to {filename}")

def parse_ports(port_string):
    """Parses port input like '21,22,80-85' into a list of ports."""
    ports = set()
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    print("Welcome to the Python Banner Grabber Tool.")
    print("You will now be asked to enter each argument step-by-step.\n")

    target_ip = input("Enter target IP or hostname: ").strip()
    port_input = input("Enter ports to scan (e.g., 21,22,80-85): ").strip()
    ports = parse_ports(port_input)

    try:
        threads = int(input("Enter number of threads to use (default is 10): ").strip())
    except ValueError:
        threads = 10

    output_file = input("Enter filename to export results as CSV (or press Enter to skip): ").strip()

    print("\nScanning in progress...")
    print(f"Target: {target_ip}")
    print(f"Ports: {ports}")
    print(f"Threads: {threads}")
    if output_file:
        print(f"Output file: {output_file}")
    print("-" * 50)

    results = scan_targets(target_ip, ports, threads=threads)

    for ip, port, banner in results:
        print(f"[{ip}:{port}] → {banner}")

    if output_file:
        export_to_csv(results, output_file)

    # Show CLI example
    print("\nTo run this script directly with command-line arguments in the future, use:")
    cmd = f"python banner_grabber.py {target_ip} -p {port_input} -t {threads}"
    if output_file:
        cmd += f" -o {output_file}"
    print(cmd)

if __name__ == "__main__":
    main()
