import scapy.all as scapy
import pandas as pd
import os

def scan_network(network_range):
    active_devices = []

    print(f"\nScanning network: {network_range}\n")

    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("IP Address\t\tMAC Address")
    print("----------------------------------------")

    for response in answered_list:
        ip = response[1].psrc
        mac = response[1].hwsrc
        print(f"{ip}\t\t{mac}")
        active_devices.append({"ip": ip, "mac": mac})

    # Convert to DataFrame and save to CSV
    df = pd.DataFrame(active_devices)
    if not os.path.exists("data"):
        os.makedirs("data")  # Create directory if it doesn't exist
    df.to_csv("data/network_scan_data.csv", index=False)

    print("\nNetwork scan results saved to data/network_scan_data.csv")
    return active_devices

import pandas as pd
import os

def save_network_data(ip, mac):
    file_path = "data/network_scan_results.csv"
    df = pd.DataFrame([[ip, mac]], columns=["ip", "mac"])

    # Overwrite if it's a new scan
    df.to_csv(file_path, index=False, mode='w')
