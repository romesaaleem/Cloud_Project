from collections import Counter
from ml_model import MLAnomalyDetector

class ThreatDetector:
    def __init__(self, parsed_logs):
        self.logs = parsed_logs
        self.detector = MLAnomalyDetector()
        
    def analyze(self):
        analyzed_threat_results = []
        ip_failed_counts = Counter([log['source_ip'] for log in self.logs if log['status'] == 'FAILED'])
        event_types_map = {'LOGIN_SUCCESS': 1, 'LOGIN_FAILED': 1, 'PORT_SCAN': 2, 'UNAUTHORIZED_ACCESS': 3, 'DATA_EXFILTRATION': 4}

        for log in self.logs:
            ip = log['source_ip']
            event_type = log['event_type']
            status = log['status']
            threat_type = "None"
            severity = "Safe"
            risk_score = 10.0
            recommendation = "No intervention necessary. Maintain baseline auditing protocols."
            
            event_id = event_types_map.get(event_type, 5)
            failed_binary = 1 if status == 'FAILED' else 0
            freq = ip_failed_counts.get(ip, 1)
            
            if event_type == 'LOGIN_FAILED' and freq >= 5:
                threat_type = "Brute Force Attack"
                severity = "High"
                risk_score = 85.0
                recommendation = "Block source IP address immediately via firewall perimeter rules. Force reset credentials and enable MFA."
            elif event_type == 'UNAUTHORIZED_ACCESS':
                threat_type = "Unauthorized Access Attempt"
                severity = "High"
                risk_score = 80.0
                recommendation = "Audit account token structures. Validate identity against directory parameters."
            elif event_type == 'DATA_EXFILTRATION':
                threat_type = "Data Exfiltration Signature"
                severity = "Critical"
                risk_score = 98.0
                recommendation = "Isolate target system asset endpoints immediately. Terminate connections and notify response admins."
            elif event_type == 'PORT_SCAN':
                threat_type = "Suspicious Reconnaissance Scan"
                severity = "Medium"
                risk_score = 55.0
                recommendation = "Blacklist external IP coordinates across perimeter boundary firewalls."
                
            if threat_type == "None":
                ml_pred, ml_score = self.detector.predict_anomaly(event_id, failed_binary, freq)
                if ml_pred == -1:
                    threat_type = f"Anomalous Behavior ({event_type})"
                    risk_score = round(ml_score * 100, 1)
                    severity = "High" if risk_score > 75 else "Low"
                    recommendation = "Review system metrics immediately. Execute context log tracing protocols."
            
            analyzed_threat_results.append({
                'timestamp': log['timestamp'], 'threat_type': threat_type, 'severity': severity, 'risk_score': risk_score, 'recommendation': recommendation
            })
        return analyzed_threat_results