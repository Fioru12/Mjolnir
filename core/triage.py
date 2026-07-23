import platform
import psutil
from datetime import datetime
from typing import Dict, Any, List

class SystemTriage:
    """
    Performs host live triage to collect running processes, active network connections,
    system information, and logged-in users during an incident response investigation.
    """

    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def collect_system_info(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "hostname": platform.node(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version()
        }

    def collect_processes(self) -> List[Dict[str, Any]]:
        processes = []
        for p in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cpu_percent', 'memory_percent']):
            try:
                info = p.info
                processes.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "exe": info.get("exe"),
                    "username": info.get("username"),
                    "cpu_percent": info.get("cpu_percent", 0.0),
                    "memory_percent": round(info.get("memory_percent", 0.0), 2)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return processes

    def collect_network_connections(self) -> List[Dict[str, Any]]:
        connections = []
        try:
            net_conns = psutil.net_connections(kind='inet')
            for conn in net_conns:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                connections.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_address": laddr,
                    "remote_address": raddr,
                    "status": conn.status,
                    "pid": conn.pid
                })
        except (psutil.AccessDenied, Exception):
            pass
        return connections

    def run_full_triage(self) -> Dict[str, Any]:
        return {
            "system_info": self.collect_system_info(),
            "processes_count": len(self.collect_processes()),
            "processes": self.collect_processes(),
            "network_connections": self.collect_network_connections()
        }
