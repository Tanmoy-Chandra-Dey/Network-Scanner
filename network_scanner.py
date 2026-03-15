# network_scanner.py

import socket
from datetime import datetime

COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy / Alt HTTP",
    8443: "HTTPS Alt"
}


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError("Invalid hostname or IP address.")


def detect_service(port: int) -> str:
    return COMMON_SERVICES.get(port, "Unknown Service")


def scan_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return result == 0


def scan_target(ip: str, start_port: int, end_port: int):
    open_ports = []

    for port in range(start_port, end_port + 1):
        if scan_port(ip, port):
            service = detect_service(port)
            open_ports.append((port, service))
            print(f"[OPEN] Port {port}: {service}")

    return open_ports


def save_results(target: str, ip: str, start_port: int, end_port: int, open_ports):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = "scan_results.txt"

    with open(filename, "w", encoding="utf-8") as file:
        file.write("Mini Network Scanner Report\n")
        file.write("=" * 28 + "\n")
        file.write(f"Target: {target}\n")
        file.write(f"Resolved IP: {ip}\n")
        file.write(f"Port Range: {start_port}-{end_port}\n")
        file.write(f"Scan Time: {timestamp}\n\n")

        if open_ports:
            file.write("Open Ports:\n")
            for port, service in open_ports:
                file.write(f"- Port {port}: {service}\n")
        else:
            file.write("No open ports found in the selected range.\n")

    return filename


def get_port_input(prompt: str) -> int:
    while True:
        try:
            port = int(input(prompt))
            if 1 <= port <= 65535:
                return port
            print("Please enter a port number between 1 and 65535.")
        except ValueError:
            print("Please enter a valid integer.")


def main():
    print("Mini Network Scanner")
    print("-" * 20)
    print("Only scan systems you own or have permission to test.\n")

    target = input("Enter target IP or hostname: ").strip()

    try:
        ip = resolve_target(target)
    except ValueError as error:
        print(f"Error: {error}")
        return

    start_port = get_port_input("Enter starting port: ")
    end_port = get_port_input("Enter ending port: ")

    if start_port > end_port:
        print("Starting port must be less than or equal to ending port.")
        return

    print(f"\nScanning target: {ip}")
    print(f"Port range: {start_port}-{end_port}\n")

    open_ports = scan_target(ip, start_port, end_port)

    print("\nScan Complete")
    print("-" * 13)
    if open_ports:
        print("Open ports found:")
        for port, service in open_ports:
            print(f"- Port {port}: {service}")
    else:
        print("No open ports found in the selected range.")

    output_file = save_results(target, ip, start_port, end_port, open_ports)
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    main()
