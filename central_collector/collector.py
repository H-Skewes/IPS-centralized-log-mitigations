import ssl
import socket
import json
import struct
import threading
import signal
import sys
import os
from datetime import datetime
from typing import Dict, List

from db import Database
from handlers.base_handler import BaseHandler
from handlers.ebpf_handler import EbpfHandler
from handlers.cron_handler import CronHandler
from handlers.arp_spoof_handler import ArpSpoofHandler
from handlers.tcp_session_handler import TcpSessionHandler


# lab config vars
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 8443
CERTFILE = "server.crt"
KEYFILE = "server.key"
DB_PATH = "lab_logs.db"


# registers handlers
def build_handlers() -> Dict[str, BaseHandler]:
    handlers = [
        EbpfHandler(),
        CronHandler(),
        ArpSpoofHandler(),
        TcpSessionHandler(),
    ]
    return {h.alert_type: h for h in handlers}

# tls server that receives logs from victims and inserts to sqlite while mitigating attack with handlers
class CentralCollector:
    def __init__(self):
        self.db = Database(DB_PATH)
        self.handlers: Dict[str, BaseHandler] = build_handlers()
        self.running = False
        self._total_received = 0
        self._total_mitigations = 0


    # starts tls listener
    def start(self):
        self.running = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # ensures certs are in dir
        if os.path.exists(CERTFILE) and os.path.exists(KEYFILE):
            context.load_cert_chain(CERTFILE, KEYFILE)
        else:
            print(f"[collector] WARNING: {CERTFILE}/{KEYFILE} not found.")
            print("[collector] Run setup_collector.sh to generate certs.")
            print("[collector] Falling back to unencrypted for lab testing.\n")
            context = None
        # sets up the socket and prints collector info
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((LISTEN_IP, LISTEN_PORT))
        server_sock.listen(20)
        print(f"[collector] Listening on {LISTEN_IP}:{LISTEN_PORT}")
        print(f"[collector] Database: {DB_PATH}")
        print(f"[collector] Handlers: {list(self.handlers.keys())}")
        print(f"[collector] Started at {datetime.utcnow().isoformat()}Z\n")
        # listening loop
        while self.running:
            try:
                server_sock.settimeout(1.0)
                try:
                    raw_conn, addr = server_sock.accept()
                    if context:
                        conn = context.wrap_socket(raw_conn, server_side=True)
                    else:
                        conn = raw_conn
                    t = threading.Thread(
                        target=self._handle_client,
                        args=(conn, addr),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[collector] Accept error: {e}")
        server_sock.close()
        self._print_stats()

    # event handler for the victims
    def _handle_client(self, conn, addr):
        source_ip = addr[0]
        print(f"[collector] Connected: {source_ip}")

        try:
            while True:
                length_bytes = self._recv_all(conn, 4)
                if not length_bytes:
                    break

                length = struct.unpack(">I", length_bytes)[0]

                if length > 10 * 1024 * 1024:
                    print(f"[collector] Oversized packet from {source_ip}, dropping")
                    break

                payload = self._recv_all(conn, length)
                if not payload:
                    break

                try:
                    events = json.loads(payload.decode("utf-8"))
                    if isinstance(events, dict):
                        events = [events]
                    self._process_events(events, source_ip)
                except json.JSONDecodeError as e:
                    print(f"[collector] JSON parse error from {source_ip}: {e}")

        except (ConnectionResetError, ssl.SSLError, OSError):
            pass
        finally:
            print(f"[collector] Disconnected: {source_ip}")
            conn.close()


    # receives all data helper for client handler
    def _recv_all(self, conn, length: int) -> bytes:
        data = b""
        while len(data) < length:
            try:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            except OSError:
                return None
        return data


    # processes events for handler storing them to db and sends mitigation handlers
    def _process_events(self, events: List[Dict], source_ip: str):
        for event in events:
            event.setdefault("source_vm", source_ip)
            alert_type = event.get("alert_type", "unknown")
            severity = event.get("severity", "unknown")
            event_id = self.db.insert_event(event)
            self._total_received += 1

            print(
                f"[collector] EVENT [{alert_type}] [{severity}] "
                f"from {event.get('source_vm')} | {event.get('description', '')[:80]}"
            )
            handler = self.handlers.get(alert_type)
            if handler:
                try:
                    result = handler.handle(event)
                    if result:
                        self._total_mitigations += 1
                        self.db.insert_mitigation(
                            alert_type=alert_type,
                            source_vm=event.get("source_vm", source_ip),
                            action=f"auto_mitigation",
                            result=result,
                            event_id=event_id,
                        )
                except Exception as e:
                    print(f"[collector] Handler error [{alert_type}]: {e}")
            else:
                if alert_type != "unknown":
                    print(f"[collector] No handler for alert_type={alert_type}")


    # gets stats from sqlite on run
    def _print_stats(self):
        stats = self.db.get_stats()
        print("\n[collector] === Final Stats ===")
        print(f"  Total events received:    {self._total_received}")
        print(f"  Total mitigations taken:  {self._total_mitigations}")
        print(f"  Events by type:           {stats.get('by_type', {})}")
        print(f"  Events by severity:       {stats.get('by_severity', {})}")
    
    # defines loop end
    def stop(self):
        self.running = False


# runs the collector ensures correct usage
def main():
    print("=" * 60)
    print("  Cloud Security Lab - Central Log Collector")
    print("=" * 60)
    print()

    if os.geteuid() != 0:
        print("[!] Run as root: sudo python3 collector.py")
        sys.exit(1)

    collector = CentralCollector()

    def handle_signal(sig, frame):
        print(f"\n[collector] Received signal {sig}, stopping...")
        collector.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    collector.start()


if __name__ == "__main__":
    main()