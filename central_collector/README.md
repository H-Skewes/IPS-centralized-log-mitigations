# Cloud Security Lab - Central Log Collector

Runs on the collector VM (10.10.0.20). Receives logs from all victim VMs,
stores them in SQLite, and executes automated detection and mitigation.

## File Structure

```
central_collector/
├── collector.py              # server that needs to be run
├── db.py                     # sqlite db manager
├── setup_collector.sh        # sets up tls connection and dependencies
├── lab_logs.db               # db table creation
├── handlers/
│   ├── __init__.py
│   ├── base_handler.py       # this is example on how to setup your handlers, look to other files if confused
│   ├── ebpf_handler.py       # ebpf injection detection and mititgation
│   └── cron_handler.py       # cron abuse detection and mitigation
```

## Setup

```bash
sudo bash setup_collector.sh
```

This generates TLS certs and an SSH key. Copy the SSH public key
to every victim VM's `/root/.ssh/authorized_keys`.

## Run

```bash
sudo python3 collector.py
```

## Query The Database

```bash
sqlite3 lab_logs.db

# All events
SELECT alert_type, severity, source_vm, description FROM events ORDER BY id DESC LIMIT 20;

# Events by type
SELECT alert_type, COUNT(*) FROM events GROUP BY alert_type;

# All mitigations taken
SELECT * FROM mitigations ORDER BY id DESC;
```

## Adding a New Handler (for teammates)

1. Create `handlers/your_handler.py` subclassing `BaseHandler`
2. Implement `alert_type`, `detect()`, and `mitigate()`
3. Import and add to `build_handlers()` in `collector.py`

### Minimal handler template:

```python
from handlers.base_handler import BaseHandler
from typing import Dict, Any, Optional

class YourHandler(BaseHandler):

    @property
    def alert_type(self) -> str:
        return "your_attack_name"  # must match collector name

    def detect(self, event: Dict[str, Any]) -> Optional[str]:
        # Return threat description string if should mitigate, else None
        if event.get("severity") == "critical":
            return f"Threat confirmed: {event.get('description')}"
        return None

    def mitigate(self, event: Dict[str, Any], threat: str) -> str:
        source_vm = event.get("source_vm")
        results = self.ssh_exec(source_vm, [
            "your mitigation command here",
        ])
        return "mitigation_executed"
```

## Architecture

```
Victim VMs (log_agent.py running)
    │
    │ TLS JSON events every 5s
    ▼
Central Collector (collector.py)
    ├── SQLite DB (lab_logs.db) ← all events stored
    ├── EbpfHandler ← detects + SSH mitigates Henry's attack
    └── CronHandler ← detects + SSH mitigates Tres's attack
              │
              │ SSH (paramiko, key-based auth)
              ▼
         Victim VM (kill process, unload eBPF, disable cron entry)
```
