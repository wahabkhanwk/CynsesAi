import os
from pathlib import Path
import subprocess
from diskcache import Cache

#cache = Cache("./cache_dir")

#@cache.memoize()
def run_zeek(pcap_path: str, output_dir_base: str = None) -> dict:
    """Run Zeek on PCAP file and parse logs"""
    if output_dir_base:
        output_dir = os.path.join(output_dir_base, "zeek_output")
    else:
        output_dir = "zeek_output"

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            ["zeek", "-C", "-r", pcap_path, f"Log::default_logdir={str(output_path.absolute())}"],
            check=True,
            capture_output=True,
            text=True
        )
        if result.stderr:
            print(f"⚠️ Zeek warnings: {result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Zeek failed: {e.stderr}")
        return {"error": f"Zeek execution failed: {e.stderr}"}

    logs = {}
    for log_file in output_path.glob("*.log"):
        try:
            with log_file.open() as f:
                logs[log_file.name] = f.readlines()
        except Exception as e:
            logs[log_file.name] = [f"Error reading log: {str(e)}"]
    return logs

#if __name__ == "__main__":
    # Replace with the path to a real PCAP file for testing
#    test_pcap = "/Users/macbook/Desktop/CynsesAI/sample2.pcap"
    # Example of running with a base directory
    # logs = run_zeek(test_pcap, output_dir_base="analysis_results/test_analysis_id")
    # Original way for standalone testing:
#    logs = run_zeek(test_pcap)
#    print("Zeek logs:", logs)
    #now print the logs
#    for log_name, lines in logs.items():
#        print(f"Log: {log_name}")
 #       for line in lines:
 #           print(line.strip())
#  print("✅ Zeek module loaded successfully")
