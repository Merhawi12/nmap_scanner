
#Import required standard libraries
import subprocess #Used to run system commands like nmap
import xml.etree.ElementTree as ET #used to parse Nmap XML output
import json #used to save scan results as JSON
import csv  #used to save scan results as CSV
from datetime import datetime #used to timestamp the report

#Target to scan (IP or domain)
TARGET = "127.0.0.1" #change target IP/domain here


def run_nmap(target):
    print(f"[+] Running Nmap scan on {target}...")
    command = ["nmap", "-sV", "-oX", "-", target]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout


def parse_nmap(xml_data):
    print("[+] Parsing scan results...")
    root = ET.fromstring(xml_data)

    findings = []

    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state").get("state")

            if state == "open":
                service = port.find("service")
                findings.append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service": service.get("name", "unknown"),
                    "product": service.get("product", "unknown"),
                    "version": service.get("version", "unknown")
                })

    return findings


def save_json(data):
    with open("results.json", "w") as f:
        json.dump(data, f, indent=4)
    print("[+] Saved results.json")


def save_csv(data):
    with open("results.csv", "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["port", "protocol", "service", "product", "version"]
        )
        writer.writeheader()
        writer.writerows(data)
    print("[+] Saved results.csv")


def generate_report(data, target):
    with open("report.txt", "w") as f:
        f.write("NMAP SECURITY SCAN REPORT\n")
        f.write("=" * 30 + "\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Date: {datetime.now()}\n\n")

        if not data:
            f.write("No open ports detected.\n")
        else:
            f.write("Open Ports & Services:\n\n")
            for item in data:
                f.write(
                    f"Port {item['port']}/{item['protocol']} - "
                    f"{item['service']} "
                    f"({item['product']} {item['version']})\n"
                )

            f.write("\nSecurity Recommendation:\n")
            f.write("- Close unused ports\n")
            f.write("- Restrict access using firewalls\n")
            f.write("- Keep services updated\n")

    print("[+] Generated report.txt")


def main():
    xml_output = run_nmap(TARGET)
    parsed_data = parse_nmap(xml_output)

    save_json(parsed_data)
    save_csv(parsed_data)
    generate_report(parsed_data, TARGET)

    print("\n[✔] Scan complete!")


if __name__ == "__main__":
    main()

