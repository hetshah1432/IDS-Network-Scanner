import nmap
import pandas as pd
import os

def scan_ports(ip):
    scanner = nmap.PortScanner()
    print(f"\n Scanning open ports for {ip}...\n")

    scanner.scan(ip, arguments='-T4 -F')
    port_data = []

    for port in scanner[ip]['tcp']:
        state = scanner[ip]['tcp'][port]['state']
        service = scanner[ip]['tcp'][port]['name']
        port_data.append([ip, port, state, service])

    df_ports = pd.DataFrame(port_data, columns=["ip", "port", "state", "service"])

    file_path = "data/port_scan_results.csv"

    # Overwrite file if it's a new scan
    df_ports.to_csv(file_path, index=False, mode='w')

    print("\n Port scan results saved to data/port_scan_results.csv")
