import asyncio
import logging
import random
import re
from googlesearch import search
import googlesearch
from fake_useragent import UserAgent
from plugins.base_plugin import BasePlugin
from engine.provider_manager import ProviderManager
import time

# Patch googlesearch user-agent globally to bypass 429 instantly
ua = UserAgent()
googlesearch.get_useragent = lambda: ua.random

class DorkingPlugin(BasePlugin):
    """
    Automates Google Dorking for various leak categories.
    """
    def __init__(self):
        self.categories = {
            "Configuration & Environment Leaks": [
                'site:{domain} filetype:env',
                'site:{domain} filetype:conf',
                'site:{domain} filetype:sql',
                'site:{domain} "index of /" + "backup"'
            ],
            "Sensitive Documents (Metadata Harvesting)": [
                'site:{domain} filetype:pdf "internal only"',
                'site:{domain} filetype:xlsx OR filetype:csv "salary" OR "employee"',
                'site:{domain} filetype:docx "confidential"'
            ],
            "Web Infrastructure & Login Portals": [
                'site:{domain} inurl:login OR inurl:admin',
                'site:{domain} inurl:wp-admin OR inurl:wp-content',
                'site:{domain} intitle:"dashboard"'
            ],
            "Public Code & Developer Leaks": [
                'site:github.com "{domain}" "API_KEY"',
                'site:pastebin.com "{domain}"',
                'site:trello.com "{domain}"'
            ]
        }

    def validate_config(self) -> bool:
        # No API key required for this scraping method
        return True

    def _execute_search(self, query):
        """Synchronous wrapper to fetch search results."""
        results = []
        try:
            # We fetch up to 10 results per dork. 
            # We manage our own sleep timer in the async loop.
            for url in search(query, num_results=10, sleep_interval=0):
                results.append(url)
        except Exception as e:
            if "429" in str(e):
                logging.warning(f"Google Rate Limit (429) hit on query '{query}'")
                raise Exception("429 Rate Limit")
            else:
                logging.error(f"Error executing dork '{query}': {e}")
        return results

    async def run(self, target: str):
        logging.info(f"Starting Google Dorking for domain: {target}")
        
        all_findings = []
        loop = asyncio.get_event_loop()

        rate_limited = False
        for category, dorks in self.categories.items():
            if rate_limited:
                break
            for dork_template in dorks:
                query = dork_template.format(domain=target)
                logging.info(f"Executing Dork: {query}")
                
                # Execute search in thread pool to avoid blocking the asyncio event loop
                try:
                    urls = await loop.run_in_executor(None, self._execute_search, query)
                except Exception as e:
                    if "429" in str(e):
                        all_findings.append({
                            "category": "System Alert",
                            "query": "RATE_LIMIT_EXCEEDED",
                            "url": "Google blocked further dorking queries for your IP (HTTP 429). Try again later.",
                            "severity": "Low"
                        })
                        ProviderManager().update_provider_state("google", "throttled_until", time.time() + (24 * 3600))
                        rate_limited = True
                        break
                    continue
                
                for url in urls:
                    # Regex Parsing to flag criticals based on file extensions or query context
                    severity = "Medium"
                    
                    # Flag Critical if matching .env or .sql extensions, or if it was from a critical dork
                    if re.search(r'\.(env|sql)(/|$|\?)', url, re.IGNORECASE) or "filetype:env" in query or "filetype:sql" in query:
                        severity = "Critical"
                    elif "github.com" in query or "pastebin.com" in query or "trello.com" in query:
                        severity = "High"
                    elif "login" in query or "admin" in query or "dashboard" in query:
                        severity = "High"

                    finding = {
                        "category": category,
                        "query": query,
                        "url": url,
                        "severity": severity
                    }
                    all_findings.append(finding)
                    logging.info(f"[{severity}] Found: {url}")
                
                # Rate Limiting
                sleep_time = random.uniform(30.0, 60.0)
                logging.debug(f"Sleeping for {sleep_time:.2f} seconds to avoid rate limits...")
                await asyncio.sleep(sleep_time)

        return {
            "total_findings": len(all_findings),
            "details": all_findings
        }
