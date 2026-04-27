import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
import uvicorn

def display_banner():
    banner = r"""
    ____       _     _     _   _      ____  ____ ___ _   _ _____ 
   |  _ \ _ __(_)___| |__ | |_(_)    / __ \/ ___|_ _| \ | |_   _|
   | | | | '__| / __| '_ \| __| |   | |  | \___ \| ||  \| | | |  
   | |_| | |  | \__ \ | | | |_| |   | |__| |___) | || |\  | | |  
   |____/|_|  |_|___/_| |_|\__|_|    \____/|____/___|_| \_| |_|  
    """
    print(banner)
    print(" [v1.0.0] - Advanced OSINT Web Framework")
    print(" Developed by Aryan Gupta\n")
    print(" Starting Web Server on http://localhost:8000 ...\n")

if __name__ == "__main__":
    display_banner()
    # Run the FastAPI application using uvicorn
    uvicorn.run("backend.api:app", host="127.0.0.1", port=8000, reload=False)
