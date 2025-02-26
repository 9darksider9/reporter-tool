import requests
import os

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_virustotal(resource):
    url = f"https://www.virustotal.com/api/v3/files/{resource}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None