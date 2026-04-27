import os
from pathlib import Path
from dotenv import load_dotenv

class Config:
    def __init__(self):
        # Load environment variables from .env file
        load_dotenv()
        
        # API Keys
        self.shodan_api_key = os.environ.get("SHODAN_API_KEY")
        self.censys_id = os.environ.get("CENSYS_ID")
        self.censys_secret = os.environ.get("CENSYS_SECRET")
        self.zoomeye_api_key = os.environ.get("ZOOMEYE_API_KEY")

        # Other Configurations
        self.root_dir = Path(__file__).parent.parent
        self.db_path = os.environ.get("DRISHTI_DB_PATH", str(self.root_dir / "drishti.db"))
        self.report_dir = os.environ.get("DRISHTI_REPORT_DIR", str(self.root_dir / "reports"))
        
    def validate(self):
        """Validates that necessary configuration is present."""
        report_path = Path(self.report_dir)
        if not report_path.exists():
            report_path.mkdir(parents=True, exist_ok=True)

# Global configuration object
config = Config()
config.validate()
