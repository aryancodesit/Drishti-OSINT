import aiohttp
import logging
import socket
import asyncio
from plugins.base_plugin import BasePlugin
from engine.config import config

class CensysPlugin(BasePlugin):
    """
    Infrastructure Intelligence: Censys API Integration
    """
    def __init__(self):
        self.api_id = config.censys_id
        self.api_secret = config.censys_secret

    def validate_config(self) -> bool:
        if not self.api_id or not self.api_secret:
            logging.error("Censys API keys are missing. Please set CENSYS_ID and CENSYS_SECRET in .env")
            return False
        return True

    def _is_valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    async def _resolve_domain_to_ip(self, domain):
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            return ip
        except socket.gaierror:
            return None

    async def run(self, target: str):
        ip_to_scan = target
        
        if not self._is_valid_ip(target):
            ip = await self._resolve_domain_to_ip(target)
            if not ip:
                 return {"error": f"Could not resolve domain {target} to an IP address."}
            ip_to_scan = ip

        logging.info(f"Querying Censys for IP: {ip_to_scan}")
        
        headers = {
            "Accept": "application/json"
        }
        
        auth = None
        if self.api_id and self.api_secret:
            auth = aiohttp.BasicAuth(self.api_id, self.api_secret)
        
        url = f"https://search.censys.io/api/v2/hosts/{ip_to_scan}"
        
        results = []
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers, auth=auth) as response:
                    if response.status == 200:
                        data = await response.json()
                        services = data.get("result", {}).get("services", [])
                        for svc in services:
                            results.append({
                                "ip": ip_to_scan,
                                "port": svc.get("port"),
                                "service": svc.get("service_name", "unknown"),
                                "product": svc.get("software", [{}])[0].get("product", "unknown") if svc.get("software") else "unknown",
                                "source": "censys",
                                "vulns": [] # Censys doesn't reliably expose free CVEs on v2 like Shodan
                            })
                    elif response.status == 401 or response.status == 403:
                         return {"error": f"Censys Auth Error ({response.status}). Key might be invalid."}
                    else:
                         return {"error": f"Censys API Error: {response.status}"}
            except Exception as e:
                logging.error(f"Error querying Censys: {e}")
                return {"error": str(e)}

        return {"services": results, "vulns": []}
