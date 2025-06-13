import requests
from diskcache import Cache

cache = Cache("./cache_dir")

@cache.memoize()
def real_threat_intel(ip: str) -> dict:
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {
        "Key": "99b0c8552352c73ac74739cf496a06d8e006ff2353d6b21d5d9a6e07f616f3d9dcc507b1eade1cca",
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers)
    return response.json()