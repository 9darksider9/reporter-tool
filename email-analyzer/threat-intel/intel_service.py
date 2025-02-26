import os
from apis.virustotal import check_virustotal
from apis.abuseipdb import check_abuseip
from apis.whois_lookup import whois_lookup
from cache_manager import cache_manager

class IntelService:
    def __init__(self):
        self.api_keys = {
            "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
            "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
        }

    def check_ip(self, ip):
        """Checks an IP address against intelligence sources."""
        cache_key = f"ip_{ip}"
        cached_result = cache_manager.get_cache(cache_key)

        if cached_result:
            return cached_result

        abuseip_result = check_abuseip(ip)
        result = {"abuseipdb": abuseip_result}

        cache_manager.set_cache(cache_key, result)
        return result

    def check_url(self, url):
        """Checks a URL against intelligence sources."""
        cache_key = f"url_{url}"
        cached_result = cache_manager.get_cache(cache_key)

        if cached_result:
            return cached_result

        virustotal_result = check_virustotal(url)
        result = {"virustotal": virustotal_result}

        cache_manager.set_cache(cache_key, result)
        return result

    def check_domain(self, domain):
        """Checks a domain's WHOIS record."""
        cache_key = f"domain_{domain}"
        cached_result = cache_manager.get_cache(cache_key)

        if cached_result:
            return cached_result

        whois_result = whois_lookup(domain)
        cache_manager.set_cache(cache_key, whois_result)
        return whois_result

# Initialize IntelService
intel_service = IntelService()