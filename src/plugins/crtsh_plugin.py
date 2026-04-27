import aiohttp
import asyncio
import dns.resolver
from plugins.base_plugin import BasePlugin
from engine.config import config
import logging
import shodan
import aiohttp

class CrtshPlugin(BasePlugin):
    """
    Passive Reconnaissance: Subdomain enumeration using crt.sh
    and resolution via dnspython.
    """
    def __init__(self):
        self.base_url = "https://crt.sh/"

    def validate_config(self) -> bool:
        # crt.sh doesn't require an API key
        return True

    async def _resolve_subdomain(self, subdomain: str) -> dict:
        """Asynchronously resolve a single subdomain."""
        loop = asyncio.get_event_loop()
        try:
            # Run dns resolution in a thread pool since dnspython's async support 
            # can sometimes be tricky to setup cleanly across platforms
            answers = await loop.run_in_executor(None, dns.resolver.resolve, subdomain, 'A')
            ips = [rdata.address for rdata in answers]
            return {"subdomain": subdomain, "ips": ips, "status": "resolved"}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.name.EmptyLabel):
            return {"subdomain": subdomain, "ips": [], "status": "unresolved"}
        except Exception as e:
            return {"subdomain": subdomain, "ips": [], "status": f"error: {str(e)}"}

    async def _shodan_fallback(self, target: str):
        """Fallback to Shodan DNS enumeration if crt.sh is down."""
        logging.info(f"crt.sh is down. Falling back to Shodan DNS API for {target}...")
        if not config.shodan_api_key:
             logging.error("Shodan API key missing. Cannot perform fallback.")
             return {"error": "crt.sh failed and Shodan fallback unavailable."}
             
        loop = asyncio.get_event_loop()
        subdomains = set()
        try:
             api = shodan.Shodan(config.shodan_api_key)
             # Shodan DNS endpoint returns a dict with 'data'
             domain_info = await loop.run_in_executor(None, api.dns.domain_info, target)
             for record in domain_info.get("data", []):
                 sub = record.get("subdomain")
                 if sub:
                      # If the subdomain is just 'www', full domain is 'www.target.com'
                      full_domain = f"{sub}.{target}"
                      subdomains.add(full_domain)
             return subdomains
        except Exception as e:
             logging.error(f"Shodan Fallback Error: {e}")
             return set()

    async def _hackertarget_fallback(self, target: str):
        """Level 3 Fallback: HackerTarget Host Search."""
        logging.info(f"Level 3 Fallback to HackerTarget API for {target}...")
        url = f"https://api.hackertarget.com/hostsearch/?q={target}"
        try:
             async with aiohttp.ClientSession() as session:
                 async with session.get(url) as response:
                     if response.status == 200:
                         text = await response.text()
                         subdomains = set()
                         for line in text.split('\n'):
                             if ',' in line:
                                 sub = line.split(',')[0].strip()
                                 if sub:
                                     subdomains.add(sub)
                         return subdomains
                     else:
                         return {"error": f"HackerTarget failed with status {response.status}"}
        except Exception as e:
             logging.error(f"HackerTarget Fallback Error: {e}")
             return set()

    async def run(self, target: str):
        logging.info(f"Querying crt.sh for domain: {target}")
        subdomains = set()
        
        params = {
            "q": f"%.{target}",
            "output": "json"
        }

        max_retries = 3
        retry_delay = 5

        async with aiohttp.ClientSession() as session:
            for attempt in range(max_retries):
                try:
                    async with session.get(self.base_url, params=params, timeout=30) as response:
                        if response.status == 200:
                            data = await response.json()
                            for entry in data:
                                name_value = entry.get("name_value", "")
                                for sub in name_value.split('\n'):
                                    sub = sub.strip()
                                    if not sub.startswith("*.") and sub.endswith(target):
                                        subdomains.add(sub)
                            break # Success, break out of retry loop
                        elif response.status in [502, 503]:
                            logging.warning(f"crt.sh returned {response.status}. Retrying in {retry_delay}s... (Attempt {attempt+1}/{max_retries})")
                            if attempt == max_retries - 1:
                                raise Exception(f"crt.sh persistent {response.status} error")
                            await asyncio.sleep(retry_delay)
                        else:
                            logging.error(f"crt.sh returned status code {response.status}")
                            raise Exception(f"crt.sh API error: {response.status}")
                except Exception as e:
                    logging.error(f"Error querying crt.sh: {e}")
                    if attempt == max_retries - 1:
                        # Fallback to Shodan
                        fallback_subs = await self._shodan_fallback(target)
                        if isinstance(fallback_subs, set) and fallback_subs:
                            subdomains = fallback_subs
                            break
                            
                        # Level 3 Fallback HackerTarget
                        ht_subs = await self._hackertarget_fallback(target)
                        if isinstance(ht_subs, set) and ht_subs:
                            subdomains = ht_subs
                            break
                        elif isinstance(ht_subs, dict) and "error" in ht_subs:
                            return ht_subs
                            
                        return {"error": f"crt.sh, Shodan, and HackerTarget fallbacks failed."}
                    await asyncio.sleep(retry_delay)

        logging.info(f"Found {len(subdomains)} unique subdomains on crt.sh. Resolving...")

        # Resolve discovered subdomains
        tasks = [self._resolve_subdomain(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)

        # Filter and structure final output
        resolved = [r for r in results if r["status"] == "resolved"]
        unresolved = [r["subdomain"] for r in results if r["status"] == "unresolved"]

        return {
            "total_found": len(subdomains),
            "total_resolved": len(resolved),
            "resolved_subdomains": resolved,
            "unresolved_subdomains": unresolved
        }
