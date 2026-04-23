"""
handlers/cron_handler.py

Detection and mitigation handler for unauthorized cron job attacks.

Incorporates Tres's detection and mitigation logic from D_M_functions.py,
adapted to work within the BaseHandler OOP pattern and the central
collector's SSH-based remote mitigation architecture.

Tres's functions preserved:
  - is_high_frequency()
  - executes_from_writable_dir()
  - accesses_sensitive_file()
  - contains_suspicious_token()
  - evaluate_entry()
  - kill_payload_processes() -> adapted as remote SSH command
  - comment_out_matching_line() -> adapted as remote SSH command
  - remediate() -> becomes mitigate()
"""

import os
import json
import shlex
from typing import Dict, Any, Optional, List, NamedTuple
from handlers.base_handler import BaseHandler


# ----------------------------------------------------------------
# Constants from Tres's original code
# ----------------------------------------------------------------

WRITABLE_DIRS = [
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/user",
    "/home",
]

SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/root/.ssh",
    "/etc/sudoers",
    "/.ssh/authorized_keys",
    "/proc/",
]

SUSPICIOUS_TOKENS = [
    "curl",
    "wget",
    "bash -i",
    "nc ",
    "netcat",
    "python -c",
    "python3 -c",
    "perl -e",
    "ruby -e",
    "chmod +x",
    "/dev/tcp",
    "base64 -d",
    "eval",
    "exec",
    "nohup",
]

ALLOWLIST_FILES = {
    "cron",
    "crontab",
    "e2scrub_all",
    "sysstat",
    "logrotate",
    "apt",
    "dpkg",
}

# Minimum number of reasons from evaluate_entry() before mitigating
# Tres's design: don't flag on a single indicator
MIN_REASONS_TO_MITIGATE = 2


class CronEntry(NamedTuple):
    """Mirrors the CronEntry from the collector side"""
    schedule: str
    user: str
    command: str
    raw_line: str
    source_file: str
    payload_preview: str


class CronHandler(BaseHandler):
    """
    Handles detection and remote mitigation for cron job abuse events.
    Tres's evaluate_entry() logic runs here on the collector side,
    providing a second layer of behavioral analysis beyond what the
    collector agent detected.
    """

    @property
    def alert_type(self) -> str:
        return "cron_abuse"

    def detect(self, event: Dict[str, Any]) -> Optional[str]:
        """
        Re-evaluate the incoming event using Tres's behavioral detection logic.
        Only mitigate if multiple malicious indicators are present.
        """
        # Reconstruct a CronEntry from the event fields
        entry = CronEntry(
            schedule=event.get("schedule", ""),
            user=event.get("user", "unknown"),
            command=event.get("command", ""),
            raw_line=event.get("raw_line", ""),
            source_file=event.get("source_file", ""),
            payload_preview=event.get("payload_preview", ""),
        )

        reasons = self.evaluate_entry(entry)

        if len(reasons) >= MIN_REASONS_TO_MITIGATE:
            return (
                f"Malicious cron entry confirmed ({len(reasons)} indicators): "
                f"{', '.join(reasons)} | command={entry.command}"
            )

        if reasons:
            print(
                f"[{self.alert_type}] Low confidence ({len(reasons)} indicator): "
                f"{reasons} — monitoring only"
            )

        return None

    def mitigate(self, event: Dict[str, Any], threat_description: str) -> str:
        """
        SSH into the victim VM and execute Tres's remediate() logic remotely:
        1. Comment out the malicious cron entry (safer than deleting)
        2. Kill any payload processes running from writable dirs
        3. Log the action on the victim VM
        """
        source_vm = event.get("source_vm", "unknown")
        source_file = event.get("source_file", "")
        raw_line = event.get("raw_line", "")
        command = event.get("command", "")

        actions_taken = []
        commands = []

        # 1. Comment out the malicious cron entry
        # Replicates Tres's comment_out_matching_line() remotely via Python one-liner
        if source_file and raw_line:
            escaped_line = shlex.quote(raw_line)
            escaped_file = shlex.quote(source_file)
            python_cmd = (
                f"python3 -c \""
                f"import os; "
                f"path={escaped_file}; "
                f"target={escaped_line}; "
                f"lines=open(path).readlines() if os.path.exists(path) else []; "
                f"new=[('# DISABLED_BY_HIDS '+l) if l.strip()==target and not l.lstrip().startswith('#') else l for l in lines]; "
                f"open(path,'w').writelines(new) if lines else None\""
            )
            commands.append(python_cmd)
            actions_taken.append(f"commented_out_entry_in={source_file}")

        # 2. Kill payload processes executing from writable directories
        # Replicates Tres's kill_payload_processes() — searches for processes
        # running scripts from known writable dirs
        for writable_dir in WRITABLE_DIRS:
            if writable_dir in command:
                # Extract the script path from the command to kill specifically
                script_path = self._extract_script_path(command, writable_dir)
                if script_path:
                    kill_cmd = (
                        f"ps -eo pid,args | grep {shlex.quote(script_path)} | "
                        f"grep -v grep | awk '{{print $1}}' | "
                        f"xargs -r kill -SIGTERM 2>/dev/null || true"
                    )
                    commands.append(kill_cmd)
                    actions_taken.append(f"killed_processes_running={script_path}")

        # 3. Also kill any process matching the full command string
        if command:
            safe_cmd = shlex.quote(command[:50])  # truncate for safety
            commands.append(
                f"ps -eo pid,args | grep {safe_cmd} | grep -v grep | "
                f"awk '{{print $1}}' | xargs -r kill -SIGTERM 2>/dev/null || true"
            )

        # 4. Log the mitigation on the victim VM
        commands.append(
            f"echo '[HIDS] Cron abuse mitigated at $(date -u): "
            f"{shlex.quote(threat_description[:100])}' "
            f">> /var/log/hids_mitigations.log"
        )

        # Execute via SSH
        if commands:
            results = self.ssh_exec(source_vm, commands)
            if "_error" in results:
                actions_taken.append(f"ssh_error={results['_error']}")

        return " | ".join(actions_taken) if actions_taken else "no_actions_taken"

    # ----------------------------------------------------------------
    # Tres's detection functions, preserved exactly, adapted as methods
    # ----------------------------------------------------------------

    def is_high_frequency(self, schedule: str) -> bool:
        return schedule.strip() == "* * * * *"

    def executes_from_writable_dir(self, command: str) -> bool:
        lowered = command.lower()
        return any(wd.lower() in lowered for wd in WRITABLE_DIRS)

    def accesses_sensitive_file(self, command: str, payload_preview: str) -> bool:
        combined = f"{command}\n{payload_preview}".lower()
        return any(path.lower() in combined for path in SENSITIVE_FILES)

    def contains_suspicious_token(self, command: str, payload_preview: str) -> bool:
        combined = f"{command}\n{payload_preview}".lower()
        return any(token in combined for token in SUSPICIOUS_TOKENS)

    def evaluate_entry(self, entry: CronEntry) -> List[str]:
        """
        Behavior-based detection — Tres's logic preserved exactly.
        Does NOT flag just because a cron job exists.
        Flags only when multiple malicious indicators are present.
        """
        reasons = []

        if self.is_high_frequency(entry.schedule):
            reasons.append("runs every minute")

        if self.executes_from_writable_dir(entry.command):
            reasons.append("executes from writable directory")

        if self.accesses_sensitive_file(entry.command, entry.payload_preview):
            reasons.append("accesses sensitive file")

        if self.contains_suspicious_token(entry.command, entry.payload_preview):
            reasons.append("contains suspicious command token")

        # Allowlist check — not in known safe cron files
        file_name = os.path.basename(entry.source_file)
        if file_name not in ALLOWLIST_FILES:
            reasons.append("not in known cron file allowlist")

        return reasons

    # ----------------------------------------------------------------
    # Helper
    # ----------------------------------------------------------------

    def _extract_script_path(self, command: str, writable_dir: str) -> Optional[str]:
        """Extract the script path from a command string"""
        tokens = command.split()
        for token in tokens:
            if token.startswith(writable_dir) and not token.startswith("-"):
                return token
        return None
