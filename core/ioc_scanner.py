import ipaddress
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

    @staticmethod
    def extract_ip(raddr: str) -> str:
        """
        Extract the bare IP address from a `host:port`-style remote address
        string, correctly handling IPv6.

        Formats handled:
          - "1.2.3.4:443"          -> IPv4 with port
          - "[2001:db8::1]:443"    -> bracketed IPv6 with port
          - "2001:db8::1"          -> bare IPv6 without an explicit port
                                       (has more than one ":", so it is NOT
                                       split - a plain split(":")[0] would
                                       truncate it into garbage)
          - "1.2.3.4"              -> bare IPv4

        The candidate is validated with `ipaddress`; if validation fails,
        the original raw string is returned unchanged as a safe fallback.
        """
        if not raddr:
            return raddr

        candidate = raddr
        if raddr.startswith("["):
            # Bracketed IPv6, optionally followed by ":port".
            closing = raddr.find("]")
            if closing != -1:
                candidate = raddr[1:closing]
        elif raddr.count(":") == 1:
            # Exactly one colon -> IPv4:port (or hostname:port).
            candidate = raddr.split(":", 1)[0]
        else:
            # Zero, or more than one, colon: either a bare IPv4 (0 colons)
            # or a bare IPv6 address without an explicit port (2+ colons).
            # In both cases the full string is the address - do not split.
            candidate = raddr

        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            return raddr

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
                    "pid": proc.get("pid"),
                    "details": f"Suspicious or known malicious process found (PID: {proc.get('pid')}, Path: {proc.get('exe')})"
                })

        # Check network connections
        for conn in triage_data.get("network_connections", []):
            raddr = conn.get("remote_address", "")
            remote_ip = self.extract_ip(raddr)
            if remote_ip in self.SUSPICIOUS_IPS:
                hits.append({
                    "type": "MALICIOUS_IP_CONNECTION",
                    "severity": "CRITICAL",
                    "indicator": raddr,
                    "pid": conn.get("pid"),
                    "details": f"Active network connection to known malicious IOC IP (PID: {conn.get('pid')}, Status: {conn.get('status')})"
                })

        return hits
