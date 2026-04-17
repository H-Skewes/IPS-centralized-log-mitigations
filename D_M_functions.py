@dataclass
class CronEntry:
    schedule: str
    user: str
    command: str
    raw_line: str
    source_file: str
    payload_preview: str = ""


def ensure_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            file_path TEXT NOT NULL,
            event_type TEXT NOT NULL,
            file_hash TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            file_path TEXT NOT NULL,
            raw_line TEXT NOT NULL,
            reasons TEXT NOT NULL,
            action_taken TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def log_file_event(file_path: str, event_type: str, file_hash: Optional[str]):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO file_events (ts, file_path, event_type, file_hash)
        VALUES (datetime('now'), ?, ?, ?)
    """, (file_path, event_type, file_hash))
    conn.commit()
    conn.close()


def log_alert(file_path: str, raw_line: str, reasons: List[str], action_taken: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts (ts, file_path, raw_line, reasons, action_taken)
        VALUES (datetime('now'), ?, ?, ?, ?)
    """, (file_path, raw_line, "; ".join(reasons), action_taken))
    conn.commit()
    conn.close()


def file_hash(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None


def snapshot_watch_dir() -> Dict[str, Optional[str]]:
    snapshot = {}
    if not os.path.isdir(WATCH_DIR):
        return snapshot

    for name in os.listdir(WATCH_DIR):
        full = os.path.join(WATCH_DIR, name)
        if os.path.isfile(full):
            snapshot[full] = file_hash(full)
    return snapshot


def read_payload_preview(command: str) -> str:
    """
    If command points to a readable script file, read a preview.
    This helps detect behavior inside /tmp payloads instead of only the cron line.
    """
    tokens = command.split()
    for token in tokens:
        if token.startswith("/") and os.path.isfile(token):
            try:
                with open(token, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read(500)
            except Exception:
                return ""
    return ""


def parse_cron_file(path: str) -> List[CronEntry]:
    entries = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.strip()

                if not raw or raw.startswith("#"):
                    continue

                parts = raw.split()
                if len(parts) < 7:
                    continue

                schedule = " ".join(parts[0:5])
                user = parts[5]
                command = " ".join(parts[6:])
                payload_preview = read_payload_preview(command)

                entries.append(CronEntry(
                    schedule=schedule,
                    user=user,
                    command=command,
                    raw_line=raw,
                    source_file=path,
                    payload_preview=payload_preview
                ))
    except (FileNotFoundError, PermissionError):
        pass

    return entries


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

    # Allowlist is visibility context only not enough alone
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


def diff_changed_files(old: Dict[str, Optional[str]], new: Dict[str, Optional[str]]) -> List[str]:
    changed = []
    for path, new_hash in new.items():
        if path not in old:
            changed.append(path)
        elif old[path] != new_hash:
            changed.append(path)
    return changed


def main():
    if os.geteuid() != 0:
        print("Run this HIDS with sudo.")
        return

    ensure_db()
    previous = snapshot_watch_dir()

    print("[*] HIDS started")
    print(f"[*] Monitoring: {WATCH_DIR}")
    print(f"[*] Database:   {DB_PATH}")

    while True:
        time.sleep(POLL_INTERVAL)
        current = snapshot_watch_dir()
        changed_files = diff_changed_files(previous, current)

        for path in changed_files:
            current_hash = file_hash(path)
            log_file_event(path, "modified_or_created", current_hash)

            entries = parse_cron_file(path)
            for entry in entries:
                reasons = evaluate_entry(entry)

                # Require multiple suspicious indicators
       
                if len(reasons) >= 2:
                    print(f"[ALERT] Malicious cron behavior detected in {path}")
                    print(f"        Line: {entry.raw_line}")
                    print(f"        Reasons: {', '.join(reasons)}")

                    action_taken = remediate(entry)
                    log_alert(path, entry.raw_line, reasons, action_taken)

        previous = current


if __name__ == "__main__":
    main()