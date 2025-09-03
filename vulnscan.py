import socket
import json
import argparse
from datetime import datetime

# Step 1: Load vulnerability database
with open("vulnerabilities.json", "r") as f:
    vuln_db = json.load(f)

# Step 2: Scan a single port
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Wait 1 second max
        result = sock.connect_ex((ip, port))  # Returns 0 if open
        sock.close()
        return result == 0
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return False

# Step 3: Grab service banner
def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return None

# Step 4: Check for vulnerabilities
def check_vuln(banner):
    if banner:
        for known, description in vuln_db.items():
            if known in banner:
                return description
    return "No known vulnerabilities detected"

# Step 5: Main scan function
def scan(ip, ports):
    results = []
    for port in ports:
        open_status = scan_port(ip, port)
        if open_status:
            banner = grab_banner(ip, port)
            vuln_info = check_vuln(banner)
            result = {
                "port": port,
                "banner": banner if banner else "Unknown",
                "vulnerability": vuln_info
            }
            results.append(result)
            print(f"[+] Port {port} open: {banner} | {vuln_info}")
    # Save results to JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"examples/scan_{timestamp}.json", "w") as f:
        json.dump(results, f, indent=4)
    print(f"Scan complete. Results saved to examples/scan_{timestamp}.json")

# Step 6: Argument parser for command-line usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan - Lightweight Vulnerability Scanner")
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--ports", default="20-1024", help="Port range (start-end)")
    args = parser.parse_args()
    
    start_port, end_port = map(int, args.ports.split("-"))
    port_list = range(start_port, end_port + 1)
    
    scan(args.ip, port_list)

