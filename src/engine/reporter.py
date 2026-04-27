import json
import os
from datetime import datetime
from engine.config import config

class Reporter:
    def __init__(self, target):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = config.report_dir
        self.base_filename = f"{self.target}_{self.timestamp}"

    def generate_json(self, results):
        """Generates a raw JSON export of the findings."""
        filepath = os.path.join(self.report_dir, f"{self.base_filename}.json")
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=4)
        return filepath

    def generate_markdown(self, results, diffs):
        """Generates a professional Markdown summary of the findings."""
        filepath = os.path.join(self.report_dir, f"{self.base_filename}.md")
        
        with open(filepath, 'w') as f:
            f.write(f"# OSINT Attack Surface Report: {self.target}\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("## Executive Summary\n")
            f.write("This report details the findings from the Drishti OSINT Framework scan.\n\n")

            # Calculate and display Risk Score Summary
            critical_count = 0
            high_count = 0
            medium_count = 0

            # Scan through the results for severity or vulns
            for plugin_name, data in results.items():
                if isinstance(data, dict):
                    # Check Infrastructure vulns and service severities
                    if "vulns" in data and data["vulns"]:
                        critical_count += len(data["vulns"])
                    
                    if "services" in data and isinstance(data["services"], list):
                        for svc in data["services"]:
                            sev = svc.get("severity")
                            if sev == "Critical":
                                critical_count += 1
                            elif sev == "High":
                                high_count += 1
                            elif sev == "Medium":
                                medium_count += 1
                    
                    # Check Dorking details
                    if "details" in data and isinstance(data["details"], list):
                        for item in data["details"]:
                            if item.get("severity") == "Critical":
                                critical_count += 1
                            elif item.get("severity") == "High":
                                high_count += 1
                            elif item.get("severity") == "Medium":
                                medium_count += 1
                
            f.write("### Risk Score Summary\n")
            f.write(f"- **Critical Findings:** {critical_count}\n")
            f.write(f"- **High Findings:** {high_count}\n")
            f.write(f"- **Medium Findings:** {medium_count}\n\n")

            for plugin_name, data in results.items():
                f.write(f"## {plugin_name.upper()} Findings\n")
                
                # Check for diffs
                if plugin_name in diffs:
                    new_items = diffs[plugin_name].get("new")
                    removed_items = diffs[plugin_name].get("removed")
                    
                    if new_items:
                         f.write(f"### :warning: New Findings Detected!\n")
                         f.write(f"```json\n{json.dumps(new_items, indent=2)}\n```\n\n")
                    if removed_items:
                         f.write(f"### :information_source: Resolved/Removed Items\n")
                         f.write(f"```json\n{json.dumps(removed_items, indent=2)}\n```\n\n")

                # Print full results
                f.write("### Full Results\n")
                if isinstance(data, list):
                    for item in data:
                        f.write(f"- {item}\n")
                elif isinstance(data, dict):
                    f.write(f"```json\n{json.dumps(data, indent=2)}\n```\n")
                else:
                    f.write(f"{data}\n")
                
                f.write("\n---\n\n")

        return filepath
