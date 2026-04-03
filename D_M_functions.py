def is_high_frequency(schedule: str) -> bool:
    return schedule == "* * * * *"


def accesses_sensitive_file(command: str) -> bool:
    lowered = command.lower()
    return any(s.lower() in lowered for s in SENSITIVE_FILES)


def executes_from_writable_dir(command: str) -> bool:
    lowered = command.lower()
    return any(w.lower() in lowered for w in WRITABLE_DIRS)


def contains_suspicious_token(command: str) -> bool:
    lowered = command.lower()
    return any(token in lowered for token in SUSPICIOUS_TOKENS)


def evaluate_entry(entry: CronEntry) -> List[str]:
    reasons = []

    file_name = os.path.basename(entry.source_file)
    if file_name not in ALLOWLIST:
        reasons.append("cron file not on allowlist")

    if is_high_frequency(entry.schedule):
        reasons.append("runs every minute")

    if accesses_sensitive_file(entry.command):
        reasons.append("accesses sensitive file")

    if executes_from_writable_dir(entry.command):
        reasons.append("executes from writable directory")

    if contains_suspicious_token(entry.command):
        reasons.append("contains suspicious command token")

    return reasons


def kill_payload_processes():
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,args"],
            capture_output=True,
            text=True,
            check=True
        )
        for line in result.stdout.splitlines()[1:]:
            if "/tmp/lab_exfil.sh" in line:
                pid_str = line.strip().split(maxsplit=1)[0]
                try:
                    os.kill(int(pid_str), signal.SIGTERM)
                except Exception:
                    pass
    except Exception:
        pass


def remediate(file_path: str) -> str:
    actions = []

    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            actions.append("deleted cron file")
        except Exception as e:
            actions.append(f"failed to delete cron file: {e}")

    kill_payload_processes()
    actions.append("attempted payload termination")

    return ", ".join(actions)