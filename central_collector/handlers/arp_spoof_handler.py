from handlers.base_handler import BaseHandler
from typing import Dict, Any, Optional


class ArpSpoofHandler(BaseHandler):

    @property
    def alert_type(self) -> str:
        return "arp_spoofing"

    def detect(self, event: Dict[str, Any]) -> Optional[str]:

        if event.get("severity") == "critical":
            return f"ARP Spoofing Detected: {event.get('description')}"

        return None

    def mitigate(self, event: Dict[str, Any], threat: str) -> str:

        source_vm = event.get("source_vm")
        attacker_ip = event.get("attacker_ip")
        gateway_ip = event.get("gateway_ip")
        real_mac = event.get("real_gateway_mac")

        commands = []

        # Block attacker
        if attacker_ip:
            commands.append(f"iptables -A INPUT -s {attacker_ip} -j DROP")

        # Restore ARP table
        if gateway_ip and real_mac:
            commands.append(f"arp -s {gateway_ip} {real_mac}")

        self.ssh_exec(source_vm, commands)

        return f"Blocked {attacker_ip} and restored ARP table"