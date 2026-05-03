from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import paramiko

# abstract class for detections and mitigations.
class BaseHandler(ABC):

    # needs ssh creds to perform mitigations
    SSH_USER = "root"
    SSH_KEY_PATH = "/root/.ssh/id_ed25519"
    SSH_TIMEOUT = 10
    # defines the type of alert so to reduce false positives
    @property
    @abstractmethod
    def alert_type(self) -> str:
        pass


    # based on alert type confirm if there is actually a threat
    @abstractmethod
    def detect(self, event: Dict[str, Any]) -> Optional[str]:
        pass
    

    # perform mitigations via ssh using bash cmds
    @abstractmethod
    def mitigate(self, event: Dict[str, Any], threat_description: str) -> str:
        pass

    # acts as entry way to other handlers
    def handle(self, event: Dict[str, Any]) -> Optional[str]:
        threat = self.detect(event)
        if threat:
            print(f"[{self.alert_type}] THREAT CONFIRMED: {threat}")
            result = self.mitigate(event, threat)
            print(f"[{self.alert_type}] MITIGATION: {result}")
            return result
        return None


    # handles ssh connection
    def ssh_exec(self, host: str, commands: List[str]) -> Dict[str, str]:
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

    # reports alert type
    def __repr__(self):
        return f"{self.__class__.__name__}(alert_type={self.alert_type})"
