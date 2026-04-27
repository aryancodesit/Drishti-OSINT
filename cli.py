import argparse
import asyncio
import logging
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from engine.orchestrator import Orchestrator
from plugins.crtsh_plugin import CrtshPlugin
from plugins.shodan_plugin import ShodanPlugin
from plugins.dorking_plugin import DorkingPlugin

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def display_banner():
    banner = r"""
    ____       _     _     _   _      ____  ____ ___ _   _ _____ 
   |  _ \ _ __(_)___| |__ | |_(_)    / __ \/ ___|_ _| \ | |_   _|
   | | | | '__| / __| '_ \| __| |   | |  | \___ \| ||  \| | | |  
   | |_| | |  | \__ \ | | | |_| |   | |__| |___) | || |\  | | |  
   |____/|_|  |_|___/_| |_|\__|_|    \____/|____/___|_| \_| |_|  
    """
    print(banner)
    print(" [v1.0.0] - Advanced OSINT & Attack Surface Mapper")
    print(" Developed by Aryan Gupta\n")

async def main():
    parser = argparse.ArgumentParser(description="Drishti OSINT - Attack Surface Mapping Framework")
    
    # Target arguments
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    target_group.add_argument("-i", "--ip", help="Target IP address (e.g., 8.8.8.8)")

    # Plugin arguments
    parser.add_argument("--shodan", action="store_true", help="Run Shodan Infrastructure scan")
    parser.add_argument("--crtsh", action="store_true", help="Run crt.sh Subdomain Discovery")
    parser.add_argument("--dork", action="store_true", help="Run Google Dorking scan")
    
    args = parser.parse_args()

    target = args.domain or args.ip
    plugins_to_run = []

    # If no plugins specified, we could run a default set based on target type
    run_all = not (args.shodan or args.crtsh or args.dork)

    if args.domain:
        if args.crtsh or run_all:
            plugins_to_run.append(CrtshPlugin())
        if args.dork or run_all:
            plugins_to_run.append(DorkingPlugin())
        # Note: Shodan typically takes IP, but could take domain and resolve it. 
        # For simplicity, we'll assign it to IP mostly, but let user force it.
        if args.shodan:
             plugins_to_run.append(ShodanPlugin())
             
    elif args.ip:
        if args.shodan or run_all:
            plugins_to_run.append(ShodanPlugin())
        if args.crtsh or args.dork:
             logging.warning("crt.sh and Dorking plugins require a domain target. Skipping them for IP target.")

    if not plugins_to_run:
         logging.error("No valid plugins selected for the given target type.")
         sys.exit(1)

    orchestrator = Orchestrator(target, plugins_to_run)
    await orchestrator.run_all()

if __name__ == "__main__":
    display_banner()
    asyncio.run(main())
