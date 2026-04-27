import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
import asyncio
import logging
from engine.orchestrator import Orchestrator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def main():
    target = "nasa.com"
    plugins = ["infrastructure", "crtsh", "dork"]
    orch = Orchestrator(target, plugins)
    results = await orch.run_all()
    print("\n[+] SCAN FINISHED SUCCESSFULLY!")

if __name__ == "__main__":
    asyncio.run(main())
