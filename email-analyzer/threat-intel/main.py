from fastapi import FastAPI
from apis.virustotal import check_virustotal
from apis.abuseipdb import check_abuseip

app = FastAPI()

@app.get("/check_url/{url}")
def check_url(url: str):
    return check_virustotal(url)

@app.get("/check_ip/{ip}")
def check_ip(ip: str):
    return check_abuseip(ip)