import requests

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_abuseip(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None