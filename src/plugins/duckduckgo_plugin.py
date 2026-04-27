import asyncio
import logging
import random
import re
from duckduckgo_search import DDGS
from plugins.base_plugin import BasePlugin

class DuckDuckGoPlugin(BasePlugin):
    """
    Automates DuckDuckGo Dorking for various leak categories as a fallback to Google.
    """
    def __init__(self):
        self.categories = {
            "Configuration & Environment Leaks": [
                '"index of /" "config" "{domain}"',
                '"{domain}" filetype:env',
                '"{domain}" filetype:sql'
            ],
            "Sensitive Documents (Metadata Harvesting)": [
                '"internal use only" "{domain}"',
                '"{domain}" "confidential" filetype:pdf'
            ],
            "Web Infrastructure & Login Portals": [
                'inurl:admin "{domain}"',
                'inurl:login "{domain}"'
            ],
            "Public Code & Developer Leaks": [
                'site:github.com "{domain}" "API_KEY"'
            ]
        }

    def validate_config(self) -> bool:
        return True

    def _execute_search(self, query):
        """Synchronous wrapper to fetch search results using ddgs."""
        results = []
        try:
            ddgs = DDGS()
            # ddgs.text returns an iterator of dictionaries
            search_results = ddgs.text(query, max_results=5)
            for res in search_results:
                if isinstance(res, dict) and "href" in res:
                     results.append(res["href"])
        except Exception as e:
            logging.error(f"Error executing DDG dork '{query}': {e}")
        return results

    async def run(self, target: str):
        logging.info(f"Starting DuckDuckGo Dorking for domain: {target}")
        
        all_findings = []
        loop = asyncio.get_event_loop()

        for category, dorks in self.categories.items():
            for dork_template in dorks:
                query = dork_template.format(domain=target)
                logging.info(f"Executing DDG Dork: {query}")
                
                try:
                    urls = await loop.run_in_executor(None, self._execute_search, query)
                except Exception as e:
                    logging.error(f"DDG Search Exception: {e}")
                    continue
                
                for url in urls:
                    severity = "Medium"
                    if re.search(r'\.(env|sql)(/|$|\?)', url, re.IGNORECASE) or "filetype:env" in query or "filetype:sql" in query:
                        severity = "Critical"
                    elif "github.com" in query or "pastebin.com" in query:
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
                
                # Rate Limiting for DDG
                sleep_time = random.uniform(5.0, 10.0)
                logging.debug(f"Sleeping for {sleep_time:.2f} seconds to avoid rate limits...")
                await asyncio.sleep(sleep_time)

        return {
            "total_findings": len(all_findings),
            "details": all_findings
        }
