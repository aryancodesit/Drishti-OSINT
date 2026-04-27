import sqlite3
import json
from datetime import datetime
import logging
from contextlib import closing

class Database:
    def __init__(self, db_path="drishti.db"):
        self.db_path = db_path
        self.init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initializes the SQLite database with the necessary schema."""
        query = '''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            plugin_name TEXT NOT NULL,
            data TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        '''
        with closing(self._get_connection()) as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(query)

    def insert_result(self, target, plugin_name, data):
        """Inserts a new scan result into the database."""
        query = '''
        INSERT INTO scan_results (target, plugin_name, data)
        VALUES (?, ?, ?)
        '''
        with closing(self._get_connection()) as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(query, (target, plugin_name, json.dumps(data)))

    def get_latest_results(self, target, plugin_name, max_age_hours=None):
        """Retrieves the most recent scan result for a target and plugin."""
        query = '''
        SELECT data, timestamp FROM scan_results 
        WHERE target = ? AND plugin_name = ?
        ORDER BY timestamp DESC
        LIMIT 1
        '''
        with closing(self._get_connection()) as conn:
            cursor = conn.cursor()
            cursor.execute(query, (target, plugin_name))
            row = cursor.fetchone()
            if row:
                if max_age_hours is not None:
                    try:
                        # SQLite default timestamp format: YYYY-MM-DD HH:MM:SS
                        db_time = datetime.strptime(row['timestamp'], "%Y-%m-%d %H:%M:%S")
                        age_hours = (datetime.now() - db_time).total_seconds() / 3600
                        if age_hours > max_age_hours:
                            return None # Data is too old
                    except Exception as e:
                        logging.error(f"Error parsing timestamp: {e}")
                return json.loads(row['data'])
            return None

    def get_diff(self, target, plugin_name, current_data):
        """
        Compares current data against the most recent historical data in the DB.
        Returns a dict highlighting what is new.
        """
        previous_data = self.get_latest_results(target, plugin_name)
        if not previous_data:
            return {"new": current_data, "removed": {}}

        # Simple diffing logic - this can be expanded based on specific plugin data structures
        diff = {"new": {}, "removed": {}}
        
        # We will implement generic list/dict diffing here
        # For simplicity, if current_data is a list of subdomains:
        if isinstance(current_data, list) and isinstance(previous_data, list):
            diff["new"] = [item for item in current_data if item not in previous_data]
            diff["removed"] = [item for item in previous_data if item not in current_data]
        elif isinstance(current_data, dict) and isinstance(previous_data, dict):
            # Shallow diff for dicts (like ports)
            for k, v in current_data.items():
                if k not in previous_data:
                    diff["new"][k] = v
                elif previous_data[k] != v:
                     diff["new"][k] = v # Value changed
            
            for k in previous_data.keys():
                if k not in current_data:
                    diff["removed"][k] = previous_data[k]
        else:
            # Fallback if structure is complex
            diff["new"] = current_data
            
        return diff
