import asyncio
import logging
from engine.database import Database
from engine.reporter import Reporter
from engine.risk_scorer import RiskScorer
from engine.provider_manager import ProviderManager

from plugins.shodan_plugin import ShodanPlugin
from plugins.censys_plugin import CensysPlugin
from plugins.zoomeye_plugin import ZoomEyePlugin
from plugins.crtsh_plugin import CrtshPlugin
from plugins.dorking_plugin import DorkingPlugin

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Orchestrator:
    def __init__(self, target, plugin_names):
        self.target = target
        self.plugin_names = plugin_names
        self.db = Database()
        self.reporter = Reporter(target)
        self.provider_manager = ProviderManager()

    async def _run_infrastructure(self):
        """Runs Shodan, Censys, and ZoomEye concurrently, merges, and scores."""
        plugin_name = "Infrastructure"
        
        # 1. Check DB Cache (Threshold: 24 hours)
        cached_data = self.db.get_latest_results(self.target, plugin_name, max_age_hours=24)
        if cached_data:
            logging.info(f"Using valid cached data for {plugin_name} (under 24 hours old).")
            return plugin_name, {"results": cached_data, "diffs": {"new": {}, "removed": {}}}

        logging.info(f"No valid cache for {plugin_name}. Determining best provider...")
        
        # 2. Dynamically Select Best Provider
        best_plugin = await self.provider_manager.select_infrastructure_provider()
        
        if not best_plugin:
            return plugin_name, {"error": "No infrastructure providers with credits available."}
            
        raw_results = [await best_plugin.run(self.target)]

        # 3. Merge Results and Remove Duplicates
        merged_services = {}
        merged_vulns = set()

        for res in raw_results:
            if isinstance(res, Exception) or "error" in res:
                if isinstance(res, Exception):
                     logging.error(f"Plugin exception: {res}")
                else:
                     logging.warning(f"Plugin returned error: {res['error']}")
                continue
            
            for svc in res.get("services", []):
                port = svc.get("port")
                if port not in merged_services:
                    merged_services[port] = svc
                else:
                    # Append source if duplicate
                    source = svc.get("source")
                    if source not in merged_services[port]["source"]:
                        merged_services[port]["source"] += f", {source}"
            
            for vuln in res.get("vulns", []):
                merged_vulns.add(vuln)

        final_data = {
            "services": list(merged_services.values()),
            "vulns": list(merged_vulns)
        }

        # 4. Risk Scorer
        final_data = RiskScorer.score_infrastructure(final_data)

        # 5. Diffs and Persistence
        diffs = self.db.get_diff(self.target, plugin_name, final_data)
        self.db.insert_result(self.target, plugin_name, final_data)

        return plugin_name, {"results": final_data, "diffs": diffs}

    async def _run_single_plugin(self, plugin_instance, max_age_hours):
        """Runs a generic single plugin with caching."""
        plugin_name = plugin_instance.__class__.__name__
        
        cached_data = self.db.get_latest_results(self.target, plugin_name, max_age_hours=max_age_hours)
        if cached_data:
            logging.info(f"Using valid cached data for {plugin_name} (under {max_age_hours} hours old).")
            return plugin_name, {"results": cached_data, "diffs": {"new": {}, "removed": {}}}

        logging.info(f"No valid cache for {plugin_name}. Querying API...")
        
        if not plugin_instance.validate_config():
             return plugin_name, {"error": "Config missing"}

        try:
            results = await plugin_instance.run(self.target)
            
            if plugin_name in ["DorkingPlugin", "DuckDuckGoPlugin"]:
                results = RiskScorer.score_dorking(results)

            diffs = self.db.get_diff(self.target, plugin_name, results)
            self.db.insert_result(self.target, plugin_name, results)
            return plugin_name, {"results": results, "diffs": diffs}
        except Exception as e:
            return plugin_name, {"error": str(e)}

    async def run_all(self):
        """Orchestrates all requested workflows concurrently."""
        tasks = []
        
        if "infrastructure" in self.plugin_names:
            tasks.append(self._run_infrastructure())
        if "crtsh" in self.plugin_names:
            tasks.append(self._run_single_plugin(CrtshPlugin(), max_age_hours=168)) # 7 days
        if "dork" in self.plugin_names:
            dork_plugin = self.provider_manager.select_dorking_provider()
            tasks.append(self._run_single_plugin(dork_plugin, max_age_hours=48)) # 48 hours

        raw_results = await asyncio.gather(*tasks)
        
        final_results = {}
        final_diffs = {}

        for plugin_name, output in raw_results:
            if "error" in output:
                final_results[plugin_name] = f"Error: {output['error']}"
            else:
                final_results[plugin_name] = output["results"]
                if output["diffs"]["new"] or output["diffs"]["removed"]:
                     final_diffs[plugin_name] = output["diffs"]

        # Keep reporter logic for file writing
        self.reporter.generate_json(final_results)
        self.reporter.generate_markdown(final_results, final_diffs)
        
        return final_results
