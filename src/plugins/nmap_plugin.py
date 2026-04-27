import nmap
import logging
import socket
import asyncio
from plugins.base_plugin import BasePlugin

class NmapPlugin(BasePlugin):
    """
    Active Reconnaissance: Local Stealth Nmap Fallback Scan.
    Executes a fast connect scan (-T4 -F) on the target IP.
    """
    def __init__(self):
        pass

    def validate_config(self) -> bool:
        return True # No API key needed for local Nmap

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

    def _run_nmap_scan(self, ip_to_scan):
        nm = nmap.PortScanner()
        try:
            # -T4 (Aggressive timing), -F (Fast, top 100 ports)
            nm.scan(ip_to_scan, arguments='-T4 -F')
            return nm
        except Exception as e:
            logging.error(f"Nmap execution failed: {e}")
            return None

    async def run(self, target: str):
        ip_to_scan = target
        
        if not self._is_valid_ip(target):
            ip = await self._resolve_domain_to_ip(target)
            if not ip:
                 return {"error": f"Could not resolve domain {target} to an IP address for Nmap scan."}
            ip_to_scan = ip

        logging.info(f"Initiating Local Nmap Scan for IP: {ip_to_scan}")
        
        loop = asyncio.get_event_loop()
        nm = await loop.run_in_executor(None, self._run_nmap_scan, ip_to_scan)
        
        if not nm:
             return {"error": "Nmap scan failed."}

        results = []
        if ip_to_scan in nm.all_hosts():
            host_data = nm[ip_to_scan]
            for proto in host_data.all_protocols():
                ports = host_data[proto].keys()
                for port in ports:
                    port_state = host_data[proto][port]['state']
                    if port_state in ['open', 'filtered']:
                        results.append({
                            "ip": ip_to_scan,
                            "port": port,
                            "service": proto, # tcp/udp
                            "product": host_data[proto][port].get('name', 'unknown'),
                            "source": "nmap",
                            "vulns": []
                        })
        
        return {"services": results, "vulns": []}
