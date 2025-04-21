from scapy.all import sniff, IP
from collections import defaultdict
import threading
import time
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='ids.log'
)

class SimpleIDS:
    def __init__(self, threshold=50, ban_time=300, verbose=False):
        self.threshold = threshold
        self.ban_time = ban_time
        self.verbose = verbose
        self.request_counts = defaultdict(int)
        self.banned_ips = {}
        self.last_reset = time.time()
        self.packet_count = 0
        self.lock = threading.Lock()
        self.running = True

    def reset_counts(self):
        while self.running:
            time.sleep(60)
            with self.lock:
                self.request_counts.clear()
                self.last_reset = time.time()
                print(f"[INFO] Reset request counts (Packets: {self.packet_count:,})")
                logging.info(f"Reset request counts - Total packets: {self.packet_count}")

    def packet_handler(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            self.packet_count += 1
            current_time = time.time()

            with self.lock:
                if src_ip in self.banned_ips:
                    if current_time - self.banned_ips[src_ip] < self.ban_time:
                        return
                    else:
                        del self.banned_ips[src_ip]
                        print(f"[+] Unbanned {src_ip}")
                        logging.info(f"Unbanned IP: {src_ip}")

                self.request_counts[src_ip] += 1
                if self.verbose:
                    print(f"[DEBUG] {src_ip} - Count: {self.request_counts[src_ip]}")

                if self.request_counts[src_ip] > self.threshold:
                    if src_ip not in self.banned_ips:
                        self.banned_ips[src_ip] = current_time
                        print(f"[!] Possible DoS from {src_ip} - Banned")
                        logging.warning(f"DoS detected from {src_ip} - Banned for {self.ban_time}s")

    def start(self):
        print("[*] Starting IDS monitoring (Windows mode)...")
        print(f"Threshold: {self.threshold} requests/minute")
        print(f"Ban time: {self.ban_time//60} minutes")
        print("Press Ctrl+C to stop.")
        logging.info(f"Windows IDS started - Threshold: {self.threshold}, Ban time: {self.ban_time}s")

        reset_thread = threading.Thread(target=self.reset_counts, daemon=True)
        reset_thread.start()

        try:
            sniff(filter="ip", prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n[INFO] Stopping IDS monitoring...")
            logging.info(f"IDS stopped - Total packets: {self.packet_count}")
            self.running = False


def main():
    parser = argparse.ArgumentParser(description="Simple IDS for Windows")
    parser.add_argument("--threshold", type=int, default=50, help="Max requests per minute per IP (default: 50)")
    parser.add_argument("--ban-time", type=int, default=300, help="Ban duration in seconds (default: 300)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    ids = SimpleIDS(threshold=args.threshold, ban_time=args.ban_time, verbose=args.verbose)
    ids.start()

if __name__ == "__main__":
    main()