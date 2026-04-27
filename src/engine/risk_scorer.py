class RiskScorer:
    """
    Evaluates consolidated findings and assigns a definitive Severity 
    (Critical, High, Medium, Low) to each finding based on exposed 
    services and vulnerabilities.
    """
    
    CRITICAL_PORTS = {21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
    MEDIUM_PORTS = {80, 8080}

    @classmethod
    def score_infrastructure(cls, data: dict) -> dict:
        """
        Takes the merged infrastructure dict containing 'services' and 'vulns'.
        Adds a 'severity' key to each service.
        """
        services = data.get("services", [])
        vulns = data.get("vulns", [])
        
        # If there are any CVEs, the overall host has critical issues.
        # But we also score individual ports.
        
        for svc in services:
            port = int(svc.get("port", 0))
            
            if port in cls.CRITICAL_PORTS:
                svc["severity"] = "High" # Exposed sensitive service
            elif port in cls.MEDIUM_PORTS:
                svc["severity"] = "Medium" # Unencrypted web traffic
            else:
                svc["severity"] = "Low"
                
            # If a service has known vulns attached (from Shodan mostly), it's Critical
            if vulns:
                 svc["severity"] = "Critical"

        data["services"] = services
        return data

    @classmethod
    def score_dorking(cls, findings: list) -> list:
        """
        Dorking plugin already adds severity, this is a placeholder 
        for future advanced scoring logic if needed.
        """
        return findings
