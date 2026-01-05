
#Import required standard libraries
import subprocess #Used to run system commands like nmap
import xml.etree.ElementTree as ET #used to parse Nmap XML output
import json #used to save scan results as JSON
import csv  #used to save scan results as CSV
from datetime import datetime #used to timestamp the report

#Target to scan (IP or domain)
TARGET = "127.0.0.1" #change target IP/domain here

#Run Nmap using subprocess
def run_nmap(target):
    print(f"[+] Running Nmap scan on {target}...")
    command = ["nmap", "-sV", "-oX", "-", target]
    #Run command and capture output
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

#Parse Nmap XML output
def parse_nmap(xml_data):
    print("[+] Parsing scan results...")
    root = ET.fromstring(xml_data)

    findings = []
 # Loop through each scanned host
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state").get("state")
            #only collect OPEN ports
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

#Save result to JSON file
def save_json(data):
    with open("results.json", "w") as f:
        json.dump(data, f, indent=4)
    print("[+] Saved results.json")

#Save result to CSV file
def save_csv(data):
    with open("results.csv", "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["port", "protocol", "service", "product", "version"]
        )
        writer.writeheader()
        writer.writerows(data)
    print("[+] Saved results.csv")

#Generate Simple security report
def generate_report(data, target):
    with open("report.txt", "w") as f:
        #report header
        f.write("NMAP SECURITY SCAN REPORT\n")
        f.write("=" * 30 + "\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Date: {datetime.now()}\n\n")
        #If no open ports found
        if not data:
            f.write("No open ports detected.\n")
        else:
            f.write("Open Ports & Services:\n\n")
            #write each open port found
            for item in data:
                f.write(
                    f"Port {item['port']}/{item['protocol']} - "
                    f"{item['service']} "
                    f"({item['product']} {item['version']})\n"
                )
            #Basic security recommendations
            f.write("\nSecurity Recommendation:\n")
            f.write("- Close unused ports\n")
            f.write("- Restrict access using firewalls\n")
            f.write("- Keep services updated\n")

    print("[+] Generated report.txt")

#Main program excution
def main():
    xml_output = run_nmap(TARGET)
    parsed_data = parse_nmap(xml_output)

    save_json(parsed_data)
    save_csv(parsed_data)
    generate_report(parsed_data, TARGET)

    print("\n[✔] Scan complete!")

#Entry point check
if __name__ == "__main__":
    main()

