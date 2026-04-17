def is_high_frequency(schedule: str) -> bool:
    return schedule.strip() == "* * * * *"


def executes_from_writable_dir(command: str) -> bool:
    lowered = command.lower()
    return any(wd.lower() in lowered for wd in WRITABLE_DIRS)


def accesses_sensitive_file(command: str, payload_preview: str) -> bool:
    combined = f"{command}\n{payload_preview}".lower()
    return any(path.lower() in combined for path in SENSITIVE_FILES)


def contains_suspicious_token(command: str, payload_preview: str) -> bool:
    combined = f"{command}\n{payload_preview}".lower()
    return any(token in combined for token in SUSPICIOUS_TOKENS)


def evaluate_entry(entry: CronEntry) -> List[str]:
    """
    Behavior-based detection:
    do NOT flag just because a cron job exists.
    Flag only when multiple malicious indicators are present.
    """
    reasons = []

    if is_high_frequency(entry.schedule):
        reasons.append("runs every minute")

    if executes_from_writable_dir(entry.command):
        reasons.append("executes from writable directory")

    if accesses_sensitive_file(entry.command, entry.payload_preview):
        reasons.append("accesses sensitive file")

    if contains_suspicious_token(entry.command, entry.payload_preview):
        reasons.append("contains suspicious command token")

    # Allowlist is visibility and context only not enough alone
    file_name = os.path.basename(entry.source_file)
    if file_name not in ALLOWLIST_FILES:
        reasons.append("not in known cron file allowlist")

    return reasons


def kill_payload_processes() -> int:
    killed = 0
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
                    killed += 1
                except Exception:
                    pass
    except Exception:
        pass
    return killed


def comment_out_matching_line(file_path: str, raw_line: str) -> bool:
    """
    Safer mitigation than deleting all cron jobs:
    comment out only the flagged entry.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        changed = False
        new_lines = []

        for line in lines:
            if line.strip() == raw_line and not line.lstrip().startswith("#"):
                new_lines.append("# DISABLED_BY_HIDS " + line)
                changed = True
            else:
                new_lines.append(line)

        if changed:
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

        return changed
    except Exception:
        return False


def remediate(entry: CronEntry) -> str:
    actions = []

    disabled = comment_out_matching_line(entry.source_file, entry.raw_line)
    actions.append(f"commented_out_entry={disabled}")

    killed = kill_payload_processes()
    actions.append(f"killed_processes={killed}")

    return ", ".join(actions)
