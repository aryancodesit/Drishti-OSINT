import shodan
import asyncio
from plugins.base_plugin import BasePlugin
from engine.config import config
import logging
import socket

class ShodanPlugin(BasePlugin):
    """
    Infrastructure Intelligence: Shodan API Integration
    Identifies open ports, services, and CVEs associated with an IP.
    """
    def __init__(self):
        self.api_key = config.shodan_api_key
        self.api = shodan.Shodan(self.api_key) if self.api_key else None

    def validate_config(self) -> bool:
        if not self.api_key:
            logging.error("Shodan API key is missing. Please set SHODAN_API_KEY in .env")
            return False
        return True

    def _is_valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    async def _resolve_domain_to_ip(self, domain):
        """Helper to resolve a domain to an IP for Shodan if needed."""
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            return ip
        except socket.gaierror:
            return None

    async def run(self, target: str):
        ip_to_scan = target
        
        if not self._is_valid_ip(target):
            logging.info(f"Target '{target}' is not an IP. Attempting to resolve...")
            ip = await self._resolve_domain_to_ip(target)
            if not ip:
                 return {"error": f"Could not resolve domain {target} to an IP address."}
            ip_to_scan = ip
            logging.info(f"Resolved {target} to {ip_to_scan}")

        logging.info(f"Querying Shodan for IP: {ip_to_scan}")
        
        loop = asyncio.get_event_loop()
        try:
            # Shodan library is synchronous, run in executor
            host = await loop.run_in_executor(None, self.api.host, ip_to_scan)
            
            results = {
                "services": [],
                "vulns": host.get("vulns", [])
            }

            for item in host.get('data', []):
                service_info = {
                    "ip": ip_to_scan,
                    "port": item.get('port'),
                    "service": item.get('transport', 'tcp'),
                    "product": item.get('product', 'Unknown'),
                    "source": "shodan",
                    "vulns": []
                }
                results["services"].append(service_info)

            return results
            
        except shodan.APIError as e:
            logging.error(f"Shodan API Error: {e}")
            return {"error": str(e)}
        except Exception as e:
            logging.error(f"Unexpected error in Shodan plugin: {e}")
            return {"error": str(e)}
