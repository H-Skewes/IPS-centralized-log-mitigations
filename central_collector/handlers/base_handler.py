"""
handlers/base_handler.py

Abstract base class for all attack-specific detection and mitigation handlers.
Each attack type implements this to plug into the central collector.

Pattern mirrors the BaseCollector on the victim side — consistent OOP
interface so adding new attack handlers is straightforward.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import paramiko


class BaseHandler(ABC):
    """
    Abstract base for detection + mitigation handlers on the central collector.

    Each handler:
    1. Receives events from victim VMs matching its alert_type
    2. Runs detection logic to confirm/classify the threat
    3. Executes mitigation by SSHing into the affected VM

    To add a new attack handler:
    1. Create handlers/your_handler.py subclassing BaseHandler
    2. Implement alert_type, detect(), and mitigate()
    3. Register in collector.py
    """

    # SSH credentials for connecting back to victim VMs
    # Key-based auth — set up during VM provisioning
    SSH_USER = "root"
    SSH_KEY_PATH = "/root/.ssh/id_ed25519"
    SSH_TIMEOUT = 10

    @property
    @abstractmethod
    def alert_type(self) -> str:
        """
        The alert_type string this handler processes.
        Must match the name property of the corresponding collector.
        Example: 'ebpf_injection', 'cron_abuse'
        """
        pass

    @abstractmethod
    def detect(self, event: Dict[str, Any]) -> Optional[str]:
        """
        Analyze an incoming event and determine if mitigation is needed.

        Args:
            event: The full event dict from the victim VM

        Returns:
            A string describing the threat if mitigation should proceed,
            or None if the event doesn't warrant action (e.g. low confidence)
        """
        pass

    @abstractmethod
    def mitigate(self, event: Dict[str, Any], threat_description: str) -> str:
        """
        Execute mitigation against the affected VM.

        Args:
            event: The full event dict (contains source_vm, pid, etc.)
            threat_description: The string returned by detect()

        Returns:
            String summarizing what actions were taken
        """
        pass

    def handle(self, event: Dict[str, Any]) -> Optional[str]:
        """
        Main entry point called by the collector for each matching event.
        Runs detect() then mitigate() if threat confirmed.

        Returns mitigation result string, or None if no action taken.
        """
        threat = self.detect(event)
        if threat:
            print(f"[{self.alert_type}] THREAT CONFIRMED: {threat}")
            result = self.mitigate(event, threat)
            print(f"[{self.alert_type}] MITIGATION: {result}")
            return result
        return None

    def ssh_exec(self, host: str, commands: List[str]) -> Dict[str, str]:
        """
        SSH into a victim VM and execute a list of commands.
        Returns dict of command -> output.

        Args:
            host:     IP of the victim VM
            commands: List of shell commands to run in sequence
        """
        results = {}
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(
                host,
                username=self.SSH_USER,
                key_filename=self.SSH_KEY_PATH,
                timeout=self.SSH_TIMEOUT,
            )
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                results[cmd] = output if output else error
                print(f"[{self.alert_type}] SSH [{host}] $ {cmd}")
                if output:
                    print(f"[{self.alert_type}]   -> {output[:200]}")
        except Exception as e:
            print(f"[{self.alert_type}] SSH to {host} failed: {e}")
            results["_error"] = str(e)
        finally:
            ssh.close()

        return results

    def __repr__(self):
        return f"{self.__class__.__name__}(alert_type={self.alert_type})"
