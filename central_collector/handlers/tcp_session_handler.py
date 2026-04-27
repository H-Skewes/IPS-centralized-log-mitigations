from typing import Dict, Any, Optional
from collections import defaultdict
import time

from handlers.base_handler import BaseHandler


class TcpSessionHandler(BaseHandler):

    def __init__(self):
        self._rst_tracker = defaultdict(list)   
        self._session_map = defaultdict(set)    

    @property
    def alert_type(self) -> str:
        return "tcp_session"  

    def detect(self, event: Dict[str, Any]) -> Optional[str]:
        now = time.time()

        src_ip = event.get("src_ip")
        session_id = event.get("session_id")
        event_type = event.get("event_type")

        # check for RST flood
        if event_type == "rst" and src_ip:
            self._rst_tracker[src_ip].append(now)

            # keep only last 60 seconds
            self._rst_tracker[src_ip] = [
                t for t in self._rst_tracker[src_ip] if now - t < 60
            ]

            if len(self._rst_tracker[src_ip]) > 5:
                return f"RST burst detected from {src_ip}"

        # check for session used by multiple IPs
        if session_id and src_ip:
            self._session_map[session_id].add(src_ip)

            if len(self._session_map[session_id]) > 1:
                ips = list(self._session_map[session_id])
                return f"Session hijack detected for {session_id} from IPs {ips}"

        return None

    def mitigate(self, event: Dict[str, Any], threat_description: str) -> str:
        source_vm = event.get("source_vm")   # victim VM
        src_ip = event.get("src_ip")         # attacker IP
        session_id = event.get("session_id")

        commands = []

        # block attacker IP
        if src_ip:
            commands.append(f"iptables -A INPUT -s {src_ip} -j DROP")

        # simulate session invalidation
        if session_id:
            commands.append(f"echo 'invalidate_session {session_id}'")

        if not commands:
            return "No mitigation actions executed"

        # run commands over SSH
        result = self.ssh_exec(source_vm, commands)

        return f"Mitigation executed on {source_vm}: {list(result.keys())}"