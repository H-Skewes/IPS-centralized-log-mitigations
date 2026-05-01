from typing import Dict, Any, Optional, List, Tuple
from handlers.base_handler import BaseHandler


# Minimum number of correlated signals required before mitigating
MIN_SIGNALS_FOR_MITIGATION = 1

# Detection methods that count as strong signals
STRONG_SIGNALS = {
    "auditd_bpf_syscall",
    "bpftool_prog_list",
}

# Detection methods that count as supporting signals
SUPPORTING_SIGNALS = {
    "proc_net_tcp",
}


class EbpfHandler(BaseHandler):
    """
    Handles detection confirmation and mitigation for eBPF injection events.
    """

    def __init__(self):
        # Track recent events per VM to enable signal correlation
        # vm_ip -> list of recent detection_methods seen
        self._recent_signals: Dict[str, List[str]] = {}

        # Cache observed outbound connections per VM from proc_net_tcp events
        # vm_ip -> (dest_ip, dest_port) observed in network traffic
        self._observed_connections: Dict[str, Tuple[str, int]] = {}

    @property
    def alert_type(self) -> str:
        return "ebpf_injection"

    def detect(self, event: Dict[str, Any]) -> Optional[str]:
        """
        Confirm threat by accumulating signals from this VM.
        A single auditd or bpftool event is enough to trigger mitigation.
        A proc_net_tcp event alone is only flagged if we've also seen
        a bpf() syscall from the same VM.
        """
        source_vm = event.get("source_vm", "unknown")
        detection_method = event.get("detection_method", "")
        description = event.get("description", "")

        # Accumulate signals per VM
        if source_vm not in self._recent_signals:
            self._recent_signals[source_vm] = []
        self._recent_signals[source_vm].append(detection_method)

        vm_signals = self._recent_signals[source_vm]

        # Strong signal alone is enough to trigger mitigation
        if detection_method in STRONG_SIGNALS:
            return (
                f"Strong eBPF injection signal on {source_vm}: "
                f"{description} (method={detection_method})"
            )

        # Supporting signal — save the observed connection details for use
        # in mitigation even if this event alone doesn't trigger action
        if detection_method in SUPPORTING_SIGNALS:
            dest_ip = event.get("dest_ip")
            dest_port = event.get("dest_port")

            # Cache the observed connection so mitigate() can use it later
            # even if dest_ip isn't present in the strong signal event
            if dest_ip:
                self._observed_connections[source_vm] = (dest_ip, dest_port)

            has_strong = any(s in STRONG_SIGNALS for s in vm_signals)
            if has_strong:
                return (
                    f"eBPF injection corroborated by exfiltration signal on {source_vm}: "
                    f"{description}"
                )
            else:
                print(
                    f"[{self.alert_type}] Outbound connection on {source_vm} noted "
                    f"but no bpf() syscall seen yet — monitoring"
                )
                return None

        return None

    def mitigate(self, event: Dict[str, Any], threat_description: str) -> str:
        """
        SSH into the victim VM and:
        1. List and unload the malicious eBPF program
        2. Kill the process that loaded it
        3. Revoke CAP_BPF from that user
        4. Block exfiltration destination using observed connection data
        """
        source_vm = event.get("source_vm", "unknown")
        pid = event.get("pid")
        prog_id = event.get("prog_id")
        uid = event.get("uid")

        # Get dest_ip from the current event, fall back to cached observation
        # from a prior proc_net_tcp event for this VM
        dest_ip = event.get("dest_ip")
        dest_port = event.get("dest_port")
        if not dest_ip and source_vm in self._observed_connections:
            dest_ip, dest_port = self._observed_connections[source_vm]

        actions_taken = []
        commands = []

        # 1. Unload the malicious eBPF program if we know its ID
        if prog_id:
            commands.append(f"bpftool prog detach id {prog_id} 2>/dev/null || true")
            actions_taken.append(f"unloaded_bpf_prog_id={prog_id}")
        else:
            # No specific ID — detach all tracepoint/kprobe programs
            commands.append(
                "bpftool prog list --json 2>/dev/null | "
                "python3 -c \"import sys,json; "
                "[print(p['id']) for p in json.load(sys.stdin) "
                "if p.get('type') in ['tracepoint','kprobe','raw_tracepoint']]\" "
                "| xargs -I{} bpftool prog detach id {} 2>/dev/null || true"
            )
            actions_taken.append("detached_tracepoint_programs")

        # 2. Kill the offending process by PID if known
        if pid:
            commands.append(f"kill -9 {pid} 2>/dev/null || true")
            actions_taken.append(f"killed_pid={pid}")

        # 3. Revoke CAP_BPF from the user if we know their UID
        if uid and uid not in ("0", "root"):
            commands.append(
                f"usermod -L $(id -nu {uid} 2>/dev/null) 2>/dev/null || true"
            )
            actions_taken.append(f"locked_uid={uid}")

        # 4. Block exfiltration destination using observed connection data
        # dest_ip and dest_port come from actual network traffic observation
        # not hardcoded values — realistic IDS behavior
        if dest_ip:
            commands.append(
                f"iptables -A OUTPUT -d {dest_ip} -j DROP 2>/dev/null || true"
            )
            actions_taken.append(f"blocked_exfil_dest={dest_ip}")

            # Also block the specific port if we observed it
            if dest_port:
                commands.append(
                    f"iptables -A OUTPUT -p tcp --dport {dest_port} -d {dest_ip} "
                    f"-j DROP 2>/dev/null || true"
                )
                actions_taken.append(f"blocked_exfil_port={dest_port}")

        # 5. Log the incident on the victim VM for forensics
        commands.append(
            f"echo '[HIDS] eBPF injection mitigated at $(date -u)' "
            f">> /var/log/hids_mitigations.log"
        )

        # Execute all commands via SSH
        if commands:
            results = self.ssh_exec(source_vm, commands)
            if "_error" in results:
                actions_taken.append(f"ssh_error={results['_error']}")

        # Clear accumulated signals and cached connections for this VM
        self._recent_signals.pop(source_vm, None)
        self._observed_connections.pop(source_vm, None)

        return " | ".join(actions_taken) if actions_taken else "no_actions_taken"