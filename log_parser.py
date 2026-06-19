import re
import csv
from datetime import datetime

class LogParser:
    @staticmethod
    def parse(filepath):
        parsed_records = []
        if filepath.endswith('.csv'):
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    parsed_records.append({
                        'timestamp': row.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                        'event_type': row.get('event_type', 'UNKNOWN'),
                        'source_ip': row.get('source_ip', '0.0.0.0'),
                        'username': row.get('username', 'system'),
                        'status': row.get('status', 'SUCCESS')
                    })
            return parsed_records

        log_pattern = re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s(?P<event_type>[A-Z_]+)\s(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(?P<username>\w+)\s(?P<status>[A-Z]+)'
        )
        with open(filepath, 'r') as f:
            for line in f:
                match = log_pattern.search(line)
                if match:
                    parsed_records.append(match.groupdict())
        return parsed_records