"""
Ria's SIEM - Windows Agent
Collects Windows Event Logs and sends them to the SIEM server.
Requires Administrator privileges for Security log access.

Author: Ria
Licence: MIT
"""

import sys
import time
import socket
import argparse
import requests
import ctypes
from datetime import datetime

IS_WINDOWS = sys.platform == 'win32'

if IS_WINDOWS:
    import win32evtlog
    import win32evtlogutil
    import win32con
else:
    print("[!] Warning: Not running on Windows. Log collection will be simulated.")


# Configuration
DEFAULT_SERVER_URL = "http://localhost:5000"
DEFAULT_INTERVAL = 30
LOG_TYPES = ["Security", "System", "Application"]
MAX_EVENTS_PER_BATCH = 100


def is_admin():
    """Check if running with Administrator privileges."""
    if not IS_WINDOWS:
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def get_hostname():
    """Get the machine hostname."""
    return socket.gethostname()


def severity_to_string(event_type):
    """Convert Windows event type to readable string."""
    if not IS_WINDOWS:
        return "Information"
    
    severity_map = {
        win32con.EVENTLOG_ERROR_TYPE: "Error",
        win32con.EVENTLOG_WARNING_TYPE: "Warning",
        win32con.EVENTLOG_INFORMATION_TYPE: "Information",
        win32con.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
        win32con.EVENTLOG_AUDIT_FAILURE: "Audit Failure"
    }
    return severity_map.get(event_type, "Unknown")


def collect_windows_events(log_type, last_record_number=0, collect_existing=True):
    """
    Collect events from a Windows Event Log.
    Returns: (events list, last record number, error message or None)
    """
    events = []
    new_last_record = last_record_number
    error_msg = None
    
    if not IS_WINDOWS:
        return generate_simulated_events(log_type), 0, None
    
    try:
        handle = win32evtlog.OpenEventLog(None, log_type)
        
        total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
        oldest_record = win32evtlog.GetOldestEventLogRecord(handle)
        newest_record = oldest_record + total_records - 1 if total_records > 0 else 0
        
        # Skip existing events if requested
        if last_record_number == 0 and not collect_existing:
            win32evtlog.CloseEventLog(handle)
            return [], newest_record, None
        
        # Set read direction based on whether this is initial or incremental collection
        if last_record_number == 0:
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        else:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        events_read = 0
        found_old_events = False
        
        while events_read < MAX_EVENTS_PER_BATCH:
            event_records = win32evtlog.ReadEventLog(handle, flags, 0)
            
            if not event_records:
                break
            
            for event in event_records:
                if event.RecordNumber <= last_record_number:
                    found_old_events = True
                    if last_record_number > 0:
                        break
                    continue
                
                if event.RecordNumber > new_last_record:
                    new_last_record = event.RecordNumber
                
                try:
                    message = win32evtlogutil.SafeFormatMessage(event, log_type)
                except:
                    message = "Unable to format event message"
                
                log_entry = {
                    'timestamp': event.TimeGenerated.isoformat() if event.TimeGenerated else datetime.utcnow().isoformat(),
                    'event_id': event.EventID & 0xFFFF,
                    'log_type': log_type,
                    'severity': severity_to_string(event.EventType),
                    'source': event.SourceName,
                    'computer': event.ComputerName,
                    'message': message[:2000],
                    'record_number': event.RecordNumber,
                    'category': event.EventCategory
                }
                
                events.append(log_entry)
                events_read += 1
                
                if events_read >= MAX_EVENTS_PER_BATCH:
                    break
            
            if found_old_events and last_record_number > 0:
                break
        
        win32evtlog.CloseEventLog(handle)
        
    except Exception as e:
        error_code = getattr(e, 'winerror', None) or (e.args[0] if e.args else None)
        if error_code == 1314:
            error_msg = "Access denied - requires Administrator privileges"
        else:
            error_msg = str(e)
    
    return events, new_last_record, error_msg


def generate_simulated_events(log_type):
    """Generate simulated events for testing on non-Windows systems."""
    import random
    
    event_ids = {
        'Security': [4624, 4625, 4634, 4648, 4672, 4688, 4720, 4726],
        'System': [7045, 7036, 1074, 6008, 6005, 6006],
        'Application': [1000, 1001, 1002, 11707, 11708]
    }
    
    messages = {
        4624: "An account was successfully logged on.",
        4625: "An account failed to log on.",
        4634: "An account was logged off.",
        4648: "A logon was attempted using explicit credentials.",
        4672: "Special privileges assigned to new logon.",
        4688: "A new process has been created.",
        4720: "A user account was created.",
        4726: "A user account was deleted.",
        7045: "A new service was installed in the system.",
        7036: "The service entered the running state.",
        1074: "The process has initiated the restart of computer.",
        6008: "The previous system shutdown was unexpected.",
        1000: "Application error detected.",
        1001: "Windows Error Reporting.",
    }
    
    if random.random() < 0.3:
        return []
    
    events = []
    for _ in range(random.randint(1, 5)):
        event_id = random.choice(event_ids.get(log_type, [1000]))
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_id': event_id,
            'log_type': log_type,
            'severity': random.choice(['Information', 'Warning', 'Error']),
            'source': f"Simulated-{log_type}",
            'computer': get_hostname(),
            'message': messages.get(event_id, f"Simulated {log_type} event"),
            'record_number': random.randint(1000, 9999),
            'category': 0
        }
        events.append(event)
    
    return events


def send_logs_to_server(server_url, logs):
    """Send collected logs to the SIEM server."""
    if not logs:
        return True
    
    payload = {
        'host': get_hostname(),
        'logs': logs
    }
    
    try:
        response = requests.post(
            f"{server_url}/api/logs",
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code == 201:
            print(f"[+] Successfully sent {len(logs)} logs to server")
            return True
        else:
            print(f"[-] Server returned error: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Could not connect to server at {server_url}")
        return False
    except requests.exceptions.Timeout:
        print("[-] Connection to server timed out")
        return False
    except Exception as e:
        print(f"[-] Error sending logs: {str(e)}")
        return False


def run_agent(server_url, interval, collect_existing=True):
    """Main agent loop - collects and sends logs continuously."""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    🛡️  Ria's SIEM Agent  🛡️                   ║
    ║                       Basic SIEM POC                          ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    print(f"[+] Hostname: {get_hostname()}")
    print(f"[+] Server URL: {server_url}")
    print(f"[+] Collection interval: {interval} seconds")
    print(f"[+] Log types: {', '.join(LOG_TYPES)}")
    print(f"[+] Platform: {'Windows' if IS_WINDOWS else 'Non-Windows (Simulation Mode)'}")
    print(f"[+] Collect existing logs: {'Yes' if collect_existing else 'No'}")
    
    if IS_WINDOWS:
        if is_admin():
            print("[+] Running with Administrator privileges")
        else:
            print("[!] WARNING: Not running as Administrator!")
            print("[!] Security log collection requires admin privileges.")
            print("[!] Right-click terminal -> 'Run as Administrator'\n")
    
    print("[+] Press Ctrl+C to stop\n")
    
    last_records = {lt: 0 for lt in LOG_TYPES}
    permission_errors = set()
    total_collected = 0
    total_sent = 0
    cycle = 0
    
    try:
        while True:
            cycle += 1
            print(f"[*] Cycle #{cycle} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            all_logs = []
            
            for log_type in LOG_TYPES:
                if log_type in permission_errors:
                    print(f"    [{log_type}] Skipped (no permission)")
                    continue
                
                events, new_last_record, error = collect_windows_events(
                    log_type, 
                    last_records[log_type],
                    collect_existing=(collect_existing and cycle == 1)
                )
                
                if error:
                    if "Access denied" in error or "privilege" in error.lower():
                        permission_errors.add(log_type)
                        print(f"    [{log_type}] ❌ {error}")
                    else:
                        print(f"    [{log_type}] Error: {error}")
                elif events:
                    print(f"    [{log_type}] ✓ {len(events)} events (record: {new_last_record})")
                    all_logs.extend(events)
                    last_records[log_type] = new_last_record
                    total_collected += len(events)
                else:
                    if new_last_record > last_records[log_type]:
                        last_records[log_type] = new_last_record
                    print(f"    [{log_type}] No new events")
            
            if all_logs:
                if send_logs_to_server(server_url, all_logs):
                    total_sent += len(all_logs)
            
            print(f"[*] This cycle: {len(all_logs)} | Total: {total_collected} collected, {total_sent} sent")
            print(f"[*] Sleeping {interval}s...\n")
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\n[+] Agent stopped")
        print(f"[+] Summary: {cycle} cycles, {total_collected} collected, {total_sent} sent")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Ria's SIEM Agent - Windows Event Log Collector",
        epilog="Note: Requires Administrator privileges for Security log access."
    )
    
    parser.add_argument(
        '--server',
        type=str,
        default=DEFAULT_SERVER_URL,
        help=f'SIEM server URL (default: {DEFAULT_SERVER_URL})'
    )
    
    parser.add_argument(
        '--interval',
        type=int,
        default=DEFAULT_INTERVAL,
        help=f'Collection interval in seconds (default: {DEFAULT_INTERVAL})'
    )
    
    parser.add_argument(
        '--no-existing',
        action='store_true',
        help='Skip existing logs, only collect new events'
    )
    
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()
    run_agent(
        server_url=args.server,
        interval=args.interval,
        collect_existing=not args.no_existing
    )
