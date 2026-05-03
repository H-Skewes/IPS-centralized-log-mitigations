from typing import Dict, Any, Optional, List, Tuple
from handlers.base_handler import BaseHandler

# signal severity scaling
STRONG_SIGNALS = {
    "auditd_bpf_syscall",
    "bpftool_prog_list",
}
SUPPORTING_SIGNALS = {
    "proc_net_tcp",
}

# confirms detection and mitigates
class EbpfHandler(BaseHandler):

    # initialize signal vars
    def __init__(self):
        self._recent_signals: Dict[str, List[str]] = {}
        self._observed_connections: Dict[str, Tuple[str, int]] = {}

    @property
    def alert_type(self) -> str:
        return "ebpf_injection"

    # confirms the threat based on signal type supporting isnt enough a strong signal is enough to flag
    def detect(self, event: Dict[str, Any]) -> Optional[str]:
        source_vm = event.get("source_vm", "unknown")
        detection_method = event.get("detection_method", "")
        description = event.get("description", "")

        # adds signals per VM
        if source_vm not in self._recent_signals:
            self._recent_signals[source_vm] = []
        self._recent_signals[source_vm].append(detection_method)

        vm_signals = self._recent_signals[source_vm]

        # defines mitigation method if strong signal
        if detection_method in STRONG_SIGNALS:
            return (
                f"Strong eBPF injection signal on {source_vm}: "
                f"{description} (method={detection_method})"
            )

        #supports possible mitigation if more signals are given supporting isn't enough alone
        if detection_method in SUPPORTING_SIGNALS:
            dest_ip = event.get("dest_ip")
            dest_port = event.get("dest_port")
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

    # sshs into victim unhools malicious eBPF prog kills proc that loaded it revokes CAP_BPF from user blocks further exfil
    def mitigate(self, event: Dict[str, Any], threat_description: str) -> str:

        source_vm = event.get("source_vm", "unknown")
        pid = event.get("pid")
        prog_id = event.get("prog_id")
        uid = event.get("uid")
        dest_ip = event.get("dest_ip")
        dest_port = event.get("dest_port")
        if not dest_ip and source_vm in self._observed_connections:
            dest_ip, dest_port = self._observed_connections[source_vm]

        actions_taken = []
        commands = []

        if prog_id:
            commands.append(f"bpftool prog detach id {prog_id} 2>/dev/null || true")
            actions_taken.append(f"unloaded_bpf_prog_id={prog_id}")
        else:
            commands.append(
                "bpftool prog list --json 2>/dev/null | "
                "python3 -c \"import sys,json; "
                "[print(p['id']) for p in json.load(sys.stdin) "
                "if p.get('type') in ['tracepoint','kprobe','raw_tracepoint']]\" "
                "| xargs -I{} bpftool prog detach id {} 2>/dev/null || true"
            )
            actions_taken.append("detached_tracepoint_programs")

        if pid:
            commands.append(f"kill -9 {pid} 2>/dev/null || true")
            actions_taken.append(f"killed_pid={pid}")

        if uid and uid not in ("0", "root"):
            commands.append(
                f"usermod -L $(id -nu {uid} 2>/dev/null) 2>/dev/null || true"
            )
            actions_taken.append(f"locked_uid={uid}")


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

        # logs incident
        commands.append(
            f"echo '[HIDS] eBPF injection mitigated at $(date -u)' "
            f">> /var/log/hids_mitigations.log"
        )

        # executes all commands via SSH
        if commands:
            results = self.ssh_exec(source_vm, commands)
            if "_error" in results:
                actions_taken.append(f"ssh_error={results['_error']}")

        # clears signals post mitigation.
        self._recent_signals.pop(source_vm, None)
        self._observed_connections.pop(source_vm, None)

        return " | ".join(actions_taken) if actions_taken else "no_actions_taken"