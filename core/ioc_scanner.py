from typing import List, Dict, Any

class IOCScanner:
    """
    Scans triage telemetry for known Indicators of Compromise (IOCs),
    suspicious process names, and malicious IP addresses.
    """

    SUSPICIOUS_PROCESS_NAMES = {
        "mimikatz.exe", "nc.exe", "netcat", "ncat", "psexec.exe", 
        "pwdump.exe", "procdump.exe", "powershell_ise.exe", "beacon.exe"
    }

    SUSPICIOUS_IPS = {
        "203.0.113.50", "198.51.100.22", "185.220.101.5", "45.33.32.156"
    }

    def scan(self, triage_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits = []

        # Check processes
        for proc in triage_data.get("processes", []):
            name = (proc.get("name") or "").lower()
            if name in self.SUSPICIOUS_PROCESS_NAMES:
                hits.append({
                    "type": "SUSPICIOUS_PROCESS",
                    "severity": "HIGH",
                    "indicator": name,
                    "details": f"Suspicious or known malicious process found (PID: {proc.get('pid')}, Path: {proc.get('exe')})"
                })

        # Check network connections
        for conn in triage_data.get("network_connections", []):
            raddr = conn.get("remote_address", "")
            remote_ip = raddr.split(":")[0] if ":" in raddr else raddr
            if remote_ip in self.SUSPICIOUS_IPS:
                hits.append({
                    "type": "MALICIOUS_IP_CONNECTION",
                    "severity": "CRITICAL",
                    "indicator": raddr,
                    "details": f"Active network connection to known malicious IOC IP (PID: {conn.get('pid')}, Status: {conn.get('status')})"
                })

        return hits
