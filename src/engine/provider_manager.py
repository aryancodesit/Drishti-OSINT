import aiohttp
import asyncio
import shodan
import logging
import json
import os
import time
from engine.config import config

STATE_FILE = "drishti_state.json"

class ProviderManager:
    def __init__(self):
        self.blacklisted = set()
        self.state = self._load_state()

    def _load_state(self):
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_state(self):
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(self.state, f)
        except Exception as e:
            logging.error(f"Failed to save state: {e}")

    def update_provider_state(self, provider: str, key: str, value):
        if provider not in self.state:
            self.state[provider] = {}
        self.state[provider][key] = value
        self._save_state()

    async def _check_shodan(self):
        if "shodan" in self.blacklisted or not config.shodan_api_key:
            return -1
        try:
            loop = asyncio.get_event_loop()
            api = shodan.Shodan(config.shodan_api_key)
            info = await loop.run_in_executor(None, api.info)
            return info.get("query_credits", 0)
        except shodan.APIError as e:
            if "Access denied" in str(e) or "Invalid API key" in str(e):
                logging.warning("Shodan Auth Error. Blacklisting for session.")
                self.blacklisted.add("shodan")
            return -1
        except Exception as e:
            logging.error(f"Shodan check error: {e}")
            return -1

    async def _check_censys(self):
        if "censys" in self.blacklisted or not config.censys_id or not config.censys_secret:
            return -1
        try:
            url = "https://search.censys.io/api/v1/account"
            auth = aiohttp.BasicAuth(config.censys_id, config.censys_secret)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, auth=auth) as response:
                    if response.status == 200:
                        data = await response.json()
                        quota = data.get("quota", {})
                        allowance = quota.get("allowance", 0)
                        used = quota.get("used", 0)
                        return allowance - used
                    elif response.status in [401, 403]:
                        logging.warning("Censys Auth Error. Blacklisting for session.")
                        self.blacklisted.add("censys")
                        return -1
                    else:
                        return -1
        except Exception as e:
            logging.error(f"Censys check error: {e}")
            return -1

    async def _check_zoomeye(self):
        if "zoomeye" in self.blacklisted or not config.zoomeye_api_key:
            return -1
        try:
            url = "https://api.zoomeye.org/resources-info"
            headers = {"API-KEY": config.zoomeye_api_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        quota = data.get("quota_info", {})
                        return quota.get("remain_free_quota", 0)
                    elif response.status in [401, 403]:
                        logging.warning("ZoomEye Auth Error. Blacklisting for session.")
                        self.blacklisted.add("zoomeye")
                        return -1
                    else:
                        return -1
        except Exception as e:
            return -1

    async def select_infrastructure_provider(self):
        """Checks credits and returns the best initialized plugin."""
        from plugins.shodan_plugin import ShodanPlugin
        from plugins.censys_plugin import CensysPlugin
        from plugins.zoomeye_plugin import ZoomEyePlugin
        from plugins.nmap_plugin import NmapPlugin
        
        shodan_credits, censys_credits, zoomeye_credits = await asyncio.gather(
            self._check_shodan(),
            self._check_censys(),
            self._check_zoomeye()
        )
        
        logging.info(f"Provider Credits - Shodan: {shodan_credits}, Censys: {censys_credits}, ZoomEye: {zoomeye_credits}")
        
        providers = {
            "shodan": {"credits": shodan_credits, "plugin": ShodanPlugin},
            "censys": {"credits": censys_credits, "plugin": CensysPlugin},
            "zoomeye": {"credits": zoomeye_credits, "plugin": ZoomEyePlugin}
        }
        
        # Pick provider with max credits
        best_name = max(providers, key=lambda k: providers[k]['credits'])
        best_data = providers[best_name]
        
        if best_data['credits'] > 0:
            logging.info(f"Selecting {best_name.capitalize()} as the optimal infrastructure provider.")
            return best_data['plugin']()
        else:
            logging.error("No infrastructure providers available with credits! Falling back to Local Nmap Scan...")
            return NmapPlugin()

    def select_dorking_provider(self):
        """Selects Dorking provider based on state file (429 handling)."""
        from plugins.dorking_plugin import DorkingPlugin
        from plugins.duckduckgo_plugin import DuckDuckGoPlugin
        
        google_state = self.state.get("google", {})
        throttled_until = google_state.get("throttled_until", 0)
        
        if time.time() < throttled_until:
            logging.warning("Google throttled. Pivoting to DuckDuckGo...")
            return DuckDuckGoPlugin()
        
        logging.info("Selecting Google as the optimal Dorking provider.")
        return DorkingPlugin()
