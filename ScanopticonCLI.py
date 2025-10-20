#!/usr/bin/env python3

import sys
import os
import ctypes
import argparse
import ipaddress
import urllib.request
import urllib.error
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime

LOG_FILE = "scan_log.csv"
_WRITE_LOCK = threading.Lock()

# -------------------------
# Utilities
# -------------------------
def ensure_log_header():
    if not os.path.exists(LOG_FILE):
        with _WRITE_LOCK:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write("timestamp,status,url,details\n")

def log_result(url, status, details):
    details_str = str(details).replace("\n", "\\n").replace(",", ";")
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S},{status},{url},{details_str}\n"
    with _WRITE_LOCK:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)

def normalize_port(p):
    s = str(p).strip()
    if not s:
        return ""
    return s if s.startswith(":") else f":{s}"

def fetch(url, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
            log_result(url, resp.status, len(data))
            return (url, resp.status, len(data), None)
    except urllib.error.HTTPError as e:
        log_result(url, e.code, e.reason)
        return (url, e.code, None, str(e.reason))
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", str(e))
        log_result(url, "ERR", reason)
        return (url, "ERR", None, str(reason))
    except Exception as e:
        log_result(url, "ERR", str(e))
        return (url, "ERR", None, str(e))

def gen_urls_on_the_fly(ip_iter, ports, paths):
    for ip in ip_iter:
        for p in ports:
            for path in paths:
                yield f"http://{ip}{p}{path}"

# -------------------------
# Range parsing
# -------------------------
def parse_ip_range(args_list, include_all_addresses=False):
    """
    Accepts:
      - single CIDR: ['192.168.1.0/24']
      - dash range:  ['192.168.1.10-192.168.1.20']
      - two args:    ['192.168.1.10', '192.168.1.20']
    Returns an iterator of ipaddress.IPv4Address
    """
    if not args_list:
        raise ValueError("No range provided")

    raw = args_list[0]
    # two-arg mode: start end
    if len(args_list) >= 2 and '-' not in raw:
        start, end = args_list[0], args_list[1]
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
        if int(end_ip) < int(start_ip):
            raise ValueError("End IP must be >= start IP")
        return (ipaddress.ip_address(i) for i in range(int(start_ip), int(end_ip) + 1))

    # dash form: "start-end"
    if '-' in raw:
        a, b = raw.split('-', 1)
        start_ip = ipaddress.ip_address(a.strip())
        end_ip = ipaddress.ip_address(b.strip())
        if int(end_ip) < int(start_ip):
            raise ValueError("End IP must be >= start IP")
        return (ipaddress.ip_address(i) for i in range(int(start_ip), int(end_ip) + 1))

    # CIDR form
    net = ipaddress.ip_network(raw, strict=False)
    if include_all_addresses:
        return (ip for ip in net)
    else:
        return (ip for ip in net.hosts())

# -------------------------
# Auto-scaling thread determination
# -------------------------
def determine_thread_count(max_cap=200, io_multiplier=8, min_threads=4):
    """
    Determine optimal thread count for I/O-bound tasks:
      threads = max(min_threads, cpu_count * io_multiplier)
      threads capped at max_cap
    """
    cores = os.cpu_count() or 2
    threads = max(min_threads, cores * io_multiplier)
    if threads > max_cap:
        threads = max_cap
    return int(threads)

# -------------------------
# Windows UAC relaunch helper (optional)
# -------------------------
def is_windows_admin():
    try:
        return os.name == "nt" and ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def relaunch_as_admin():
    python_exe = sys.executable
    script = os.path.abspath(__file__)
    args = " ".join([f'"{a}"' for a in sys.argv[1:]])
    params = f'"{script}" {args}'.strip()
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", python_exe, params, None, 1)
    except Exception as e:
        print(f"[WARN] UAC relaunch failed: {e}")
    sys.exit(0)

# -------------------------
# Main scanner
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Threaded HTTP scanner with autoscaling threads")
    parser.add_argument("range", nargs="*", help="CIDR (x.x.x.x/x), dash (start-end), or two IPs (start end). If empty, default network is used.")
    parser.add_argument("--all", action="store_true", help="Include network and broadcast addresses for CIDR")
    parser.add_argument("--max-workers", type=int, default=None, help="Override max worker threads (absolute cap)")
    parser.add_argument("--multiplier", type=int, default=8, help="Threads = cpu_count * multiplier (I/O multiplier)")
    parser.add_argument("--timeout", type=int, default=5, help="Per-request timeout in seconds")
    parser.add_argument("--no-pause", action="store_true", help="Don't wait for Enter on exit (useful for non-interactive runs)")
    args = parser.parse_args()

    # -------------------------
    # CONFIG (edit here if desired)
    # -------------------------
    default_cidr = "192.168.1.0/30"

    # HTTP paths (common camera/device endpoints)
    paths = [
        "/control/userimage.html",
        "/view/viewer_index.shtml",
        "/axis-cgi/mjpg/video.cgi",
        "/view/index.shtml",
        "/control/player",
        "/view/view.shtml",
        "/control/multiview",
        "/multi.html",
        "/cgistart"
    ]

    # Ports (leading colon optional)
    ports = [
        ":80",
        ":8080",
        ":8081",
        ":81",
        ":82",
        ":1026",
        ":1024",
        ":8082",
        ":8000",
        ":9600"
    ]
    HARD_CAP = 1000  # absolute safety cap on threads
    MIN_THREADS = 4
    # -------------------------
    # End config
    # -------------------------

    # Optionally request UAC on Windows so logs to protected locations work; skip if already elevated
    if os.name == "nt" and not is_windows_admin():
        # Only relaunch if running interactively (avoid UAC popups in non-interactive environments)
        if sys.stdin and sys.stdin.isatty():
            print("[INFO] Not running as admin. Requesting elevation (UAC)...")
            relaunch_as_admin()
        else:
            # non-interactive mode: we won't relaunch automatically
            pass

    # parse ip iterator
    raw_args = args.range
    try:
        if raw_args:
            ip_iter = parse_ip_range(raw_args, include_all_addresses=args.all)
        else:
            ip_iter = parse_ip_range([default_cidr], include_all_addresses=args.all)
    except ValueError as e:
        print(f"[ERROR] {e}")
        parser.print_help()
        return

    # normalize ports/paths
    ports = [normalize_port(p) for p in ports if str(p).strip()]
    paths = [str(p).strip() for p in paths if str(p).strip()]
    if not ports or not paths:
        print("[ERROR] ports and paths must be configured in the script.")
        return

    # decide thread count
    io_mult = max(1, args.multiplier)
    suggested = determine_thread_count(max_cap=(args.max_workers or 200), io_multiplier=io_mult, min_threads=MIN_THREADS)
    # apply optional explicit cap from --max-workers if provided
    if args.max_workers:
        MAX_WORKERS = min(args.max_workers, HARD_CAP)
    else:
        MAX_WORKERS = min(suggested, HARD_CAP)

    SUBMIT_BUFFER = MAX_WORKERS * 2

    # We may want to materialize the IPs for counting if reasonably small (for progress)
    IP_LIST_THRESHOLD = 200000  # tune if you expect larger lists
    ip_list = None
    try:
        # attempt to get a small list if possible
        # if range was specified as CIDR in a single arg, we can compute size without materializing large iterators
        if raw_args and len(raw_args) == 1 and '/' in raw_args[0]:
            net = ipaddress.ip_network(raw_args[0], strict=False)
            count = net.num_addresses if args.all else net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
            if count <= IP_LIST_THRESHOLD:
                ip_list = list(parse_ip_range(raw_args, include_all_addresses=args.all))
        elif raw_args and len(raw_args) == 1 and '-' in raw_args[0]:
            a, b = raw_args[0].split('-', 1)
            start = int(ipaddress.ip_address(a.strip()))
            end = int(ipaddress.ip_address(b.strip()))
            count = end - start + 1
            if count <= IP_LIST_THRESHOLD:
                ip_list = list(parse_ip_range(raw_args, include_all_addresses=args.all))
        elif raw_args and len(raw_args) >= 2:
            start = int(ipaddress.ip_address(raw_args[0]))
            end = int(ipaddress.ip_address(raw_args[1]))
            count = end - start + 1
            if count <= IP_LIST_THRESHOLD:
                ip_list = list(parse_ip_range(raw_args, include_all_addresses=args.all))
        else:
            net = ipaddress.ip_network(default_cidr, strict=False)
            if net.num_addresses <= IP_LIST_THRESHOLD:
                ip_list = list(parse_ip_range([default_cidr], include_all_addresses=args.all))
    except Exception:
        ip_list = None

    if ip_list is not None:
        total_ips = len(ip_list)
        ip_iter_for_gen = iter(ip_list)
    else:
        total_ips = None
        ip_iter_for_gen = ip_iter  # streaming generator

    total_urls_est = (total_ips * len(ports) * len(paths)) if total_ips is not None else None

    ensure_log_header()
    print("[INFO] Scanner starting")
    print(f"[INFO] Thread selection: multiplier={io_mult}, max_workers={MAX_WORKERS}")
    if total_ips is not None:
        print(f"[INFO] IPs to scan: {total_ips}")
    else:
        print("[INFO] IPs to scan: streaming (unknown total)")
    print(f"[INFO] Ports: {ports}")
    print(f"[INFO] Paths: {len(paths)} entries")
    if total_urls_est:
        print(f"[INFO] Estimated total URLs: {total_urls_est}")
    print("----- starting scan -----")

    futures = set()
    completed = 0
    submitted = 0

    def drain_finished(finished_set):
        nonlocal completed
        for fut in finished_set:
            try:
                url, status, size, err = fut.result()
                completed += 1
                if err:
                    print(f"[{completed}] {url} -> {status} ({err})")
                else:
                    print(f"[{completed}] {url} -> {status} ({size} bytes)")
            except Exception as e:
                completed += 1
                print(f"[{completed}] [FUTURE EXC] {e}")

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
            url_gen = gen_urls_on_the_fly(ip_iter_for_gen, ports, paths)
            for url in url_gen:
                fut = exe.submit(fetch, url, timeout=args.timeout)
                futures.add(fut)
                submitted += 1

                if len(futures) >= SUBMIT_BUFFER:
                    finished, futures = wait(futures, return_when=FIRST_COMPLETED)
                    drain_finished(finished)

            # wait for remaining futures
            while futures:
                finished, futures = wait(futures, return_when=FIRST_COMPLETED)
                drain_finished(finished)

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}")

    print("----- scan finished -----")
    if not args.no_pause:
        try:
            if sys.stdin and sys.stdin.isatty():
                input("Press Enter to exit...")
        except Exception:
            pass

if __name__ == "__main__":
    main()

