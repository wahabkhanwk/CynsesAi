import os
import json
import subprocess
from diskcache import Cache
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config.settings import SURICATA_CONFIG, PCAP_FILE
# Initialize diskcache
#cache = Cache("./cache_dir")

#@cache.memoize()
def run_suricata(pcap_path: str, output_dir_base: str = None) -> list:
    """Run Suricata on PCAP file and parse results"""
    if output_dir_base:
        output_dir = os.path.join(output_dir_base, "suricata_output")
    else:
        output_dir = "suricata_output"
    os.makedirs(output_dir, exist_ok=True)
    
    #SURICATA_CONFIG = "/opt/homebrew/etc/suricata/suricata.yaml" #Rules
    # OUTPUT_DIR = "suricata_output" # This line seems redundant

    try:
        subprocess.run([
            "suricata",
            "-c", SURICATA_CONFIG, # Ensure SURICATA_CONFIG is correctly defined in config.settings or globally
            "-r", pcap_path,
            "-l", output_dir
        ], check=True)
    except Exception as e:
        print(f"[ERROR] Suricata failed: {e}")
        return []

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
    test_pcap = PCAP_FILE
    # Example of running with a base directory
    # run_suricata(test_pcap, output_dir_base="analysis_results/test_analysis_id")
    # Original way for standalone testing:
    events = run_suricata(test_pcap)
    print("Suricata analysis completed.")
    print("Suricata events:", events)
