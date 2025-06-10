import os
import subprocess
import json
from typing import List, Dict

def run_suricata(pcap_path: str) -> List[Dict]:
    """Run Suricata on PCAP file and parse results"""
    output_dir = "suricata_output"
    os.makedirs(output_dir, exist_ok=True)

# Paths - update these as needed
    SURICATA_CONFIG = "/opt/homebrew/etc/suricata/suricata.yaml"
    PCAP_PATH = "/Users/macbook/Desktop/CynsesAI/sample.pcap"
    OUTPUT_DIR = "suricata_output"

# Execute Suricata without the --set parameter
    subprocess.run([
        "suricata",
        "-c", SURICATA_CONFIG,
        "-r", PCAP_PATH,
        "-l", OUTPUT_DIR
        ], check=True)
    # Parse results
    events = []
    eve_path = os.path.join(output_dir, "eve.json")
    if os.path.exists(eve_path):
        with open(eve_path) as f:
            for line in f:
                events.append(json.loads(line))
    return events
if __name__ == "__main__":
    print("Running Suricata...")
    print(run_suricata("/Users/macbook/Desktop/CynsesAI/sample.pcap"))