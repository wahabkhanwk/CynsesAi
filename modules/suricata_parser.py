import os
import json
import subprocess
from diskcache import Cache

# Initialize diskcache
cache = Cache("./cache_dir")

@cache.memoize()
def run_suricata(pcap_path: str) -> list:
    """Run Suricata on PCAP file and parse results"""
    output_dir = "suricata_output"
    os.makedirs(output_dir, exist_ok=True)
    
    SURICATA_CONFIG = "/home/kali/NS_PROJECT/CynsesAi/suricata.yaml" #Rules
    OUTPUT_DIR = "/home/kali/NS_PROJECT/CynsesAi/modules/suricata_output"

    subprocess.run([
        "suricata",
        "-c", SURICATA_CONFIG,
        "-r", pcap_path,
        "-l", OUTPUT_DIR
    ], check=True)

    events = []
    eve_path = os.path.join(output_dir, "eve.json")
    if os.path.exists(eve_path):
        with open(eve_path) as f:
            for line in f:
                events.append(json.loads(line))
    #now i'll print the even in jsons
    print(events)
    return events

print ("✅ Suricata module loaded successfully")

if __name__ == "__main__":
    # Replace with the path to a real PCAP file for testing
    test_pcap = "/home/kali/NS_PROJECT/CynsesAi/sample.pcap"
    run_suricata(test_pcap)
    print("Suricata analysis completed.")
    #now print the events
    events = run_suricata(test_pcap)
    print("Suricata events:", events)

