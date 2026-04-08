import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime


class ThreatMapParser:
    def __init__(self, target_domain, reports_dir="reports"):
        self.target = target_domain
        self.reports_dir = reports_dir

        self.scan_data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "hosts": {}
        }

    def parse_nmap(self, host):
        ports = []
        try:
            file_path = f"{self.reports_dir}/nmap_{host}.xml"
            tree = ET.parse(file_path)

            for port in tree.getroot().findall(".//port"):
                state = port.find("state").get("state")
                if state == "open":
                    service = port.find("service")
                    ports.append({
                        "port": port.get("portid"),
                        "service": service.get("name") if service is not None else "unknown"
                    })
        except Exception:
            pass

        return ports

    def parse_text_file(self, filename):
        try:
            with open(f"{self.reports_dir}/{filename}") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception:
            return []

    def parse_host_reports(self, host):
        self.scan_data["hosts"][host] = {
            "open_ports": self.parse_nmap(host),
            "directories": self.parse_text_file(f"gobuster_{host}.txt"),
            "vulnerabilities": self.parse_text_file(f"nikto_{host}.txt"),
            "ssl_info": self.parse_text_file(f"sslscan_{host}.txt"),
            "headers": self.parse_text_file(f"curl_headers_{host}.txt")
        }

    def save_and_cleanup(self):
        print(f"\n[✔] Data parsed successfully.")
        print("[✔] Workspace retained (no deletion).")
