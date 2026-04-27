import aiohttp
import logging
import socket
import asyncio
from plugins.base_plugin import BasePlugin
from engine.config import config

class ZoomEyePlugin(BasePlugin):
    """
    Infrastructure Intelligence: ZoomEye API Integration
    """
    def __init__(self):
        self.api_key = config.zoomeye_api_key

    def validate_config(self) -> bool:
        if not self.api_key:
            logging.error("ZoomEye API key is missing. Please set ZOOMEYE_API_KEY in .env")
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

        logging.info(f"Querying ZoomEye for IP: {ip_to_scan}")
        
        headers = {
            "API-KEY": self.api_key
        }
        
        url = f"https://api.zoomeye.org/host/search?query=ip:{ip_to_scan}"
        
        results = []
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        matches = data.get("matches", [])
                        for match in matches:
                            portinfo = match.get("portinfo", {})
                            results.append({
                                "ip": ip_to_scan,
                                "port": portinfo.get("port"),
                                "service": portinfo.get("service", "unknown"),
                                "product": portinfo.get("app", "unknown"),
                                "source": "zoomeye",
                                "vulns": [] 
                            })
                    elif response.status == 401 or response.status == 403:
                         return {"error": f"ZoomEye Auth Error ({response.status}). Key might be invalid."}
                    else:
                         return {"error": f"ZoomEye API Error: {response.status}"}
            except Exception as e:
                logging.error(f"Error querying ZoomEye: {e}")
                return {"error": str(e)}

        return {"services": results, "vulns": []}
