import requests
import json
from diskcache import Cache
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config.settings import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
cache = Cache("./cache_dir")

@cache.memoize()
def real_threat_intel(ip: str) -> dict:
    def query_abuseipdb(ip: str) -> dict:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": str(e)}

    def query_virustotal(ip: str) -> dict:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": str(e)}

    vt_data = query_virustotal(ip)
    abuse_data = query_abuseipdb(ip)

    return {
        "virustotal": vt_data,
        "abuseipdb": abuse_data
    }

#if __name__ == "__main__":
#   test_ip = "193.32.162.157"
#   result = real_threat_intel(test_ip)
#   print(json.dumps(result, indent=4))
