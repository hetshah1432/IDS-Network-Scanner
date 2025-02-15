from scripts.network_scanner import scan_network
from scripts.port_scanner import scan_ports
from scripts.anomaly_detection import detect_anomalies

def main():
    network_range = "192.168.0.1/24"  # Modify based on your network
    print("\n Scanning Network...")
    
    active_devices = scan_network(network_range)
    
    if not active_devices:
        print(" No active devices found.")
        return

    print("\nScanning open ports for active devices...\n")
    for device in active_devices:
        ip = device["ip"]
        print(f"\nScanning: {ip}")
        scan_ports(ip)

    print("\n Running Anomaly Detection on Scanned Data...")
    detect_anomalies()

if __name__ == "__main__":
    main()
