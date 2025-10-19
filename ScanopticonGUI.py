#!/usr/bin/env python3
"""
scan_gui_internet_random_with_defaults.py

Tkinter GUI wrapper around a threaded HTTP scanner (standard library only).
Includes Internet-wide random scan option and uses the original scan_autoscale.py
default ports and paths as the GUI defaults.

Author: ChatGPT (GPT-5 Thinking mini)
"""
import os
import sys
import threading
import ipaddress
import urllib.request
import urllib.error
import urllib.parse
import random
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import queue

LOG_FILE_DEFAULT = "scan_log.csv"
_WRITE_LOCK = threading.Lock()

# ----------------- Original defaults from scan_autoscale.py -----------------
ORIG_DEFAULT_CIDR = "192.168.1.0/30"

ORIG_PATHS = [
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

ORIG_PORTS = [
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
# ---------------------------------------------------------------------------

def ensure_log_header(path):
    if not os.path.exists(path):
        with _WRITE_LOCK:
            with open(path, "w", encoding="utf-8") as f:
                f.write("timestamp,status,url,details\n")

def log_result_to(path, url, status, details):
    details_str = str(details).replace("\n", "\\n").replace(",", ";")
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S},{status},{url},{details_str}\n"
    with _WRITE_LOCK:
        with open(path, "a", encoding="utf-8") as f:
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
            return (url, resp.status, len(data), None)
    except urllib.error.HTTPError as e:
        return (url, e.code, None, str(e.reason))
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", str(e))
        return (url, "ERR", None, str(reason))
    except Exception as e:
        return (url, "ERR", None, str(e))

def parse_ip_range(args_list, include_all_addresses=False):
    if not args_list:
        raise ValueError("No range provided")
    raw = args_list[0]
    if len(args_list) >= 2 and '-' not in raw:
        start, end = args_list[0], args_list[1]
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
        if int(end_ip) < int(start_ip):
            raise ValueError("End IP must be >= start IP")
        return (ipaddress.ip_address(i) for i in range(int(start_ip), int(end_ip) + 1))
    if '-' in raw:
        a, b = raw.split('-', 1)
        start_ip = ipaddress.ip_address(a.strip())
        end_ip = ipaddress.ip_address(b.strip())
        if int(end_ip) < int(start_ip):
            raise ValueError("End IP must be >= start IP")
        return (ipaddress.ip_address(i) for i in range(int(start_ip), int(end_ip) + 1))
    net = ipaddress.ip_network(raw, strict=False)
    if include_all_addresses:
        return (ip for ip in net)
    else:
        return (ip for ip in net.hosts())

def random_public_ipv4_generator(count, max_attempts_per_ip=50, seed=None):
    if seed is not None and seed != "":
        random.seed(seed)
    yielded = 0
    attempts = 0
    while yielded < count and attempts < count * max_attempts_per_ip:
        attempts += 1
        rand_int = random.getrandbits(32)
        ip = ipaddress.ip_address(rand_int)
        if getattr(ip, "is_global", False):
            yielded += 1
            yield ip

def gen_urls_on_the_fly_from_iter(ip_iter, ports, paths):
    for ip in ip_iter:
        for p in ports:
            for path in paths:
                yield f"http://{ip}{p}{path}"

def determine_thread_count(max_cap=200, io_multiplier=8, min_threads=4):
    cores = os.cpu_count() or 2
    threads = max(min_threads, cores * io_multiplier)
    if threads > max_cap:
        threads = max_cap
    return int(threads)

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner GUI — Internet-wide random option (with original defaults)")
        self.stop_event = threading.Event()
        self.result_q = queue.Queue()
        self.executor = None
        self.futures = set()
        self._build_ui()
        self._poll_results()

    def _build_ui(self):
        frm = ttk.Frame(self.root, padding=8)
        frm.grid(sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        ipf = ttk.LabelFrame(frm, text="IP Range (CIDR, dash-range, or start end)")
        ipf.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        ipf.columnconfigure(1, weight=1)

        ttk.Label(ipf, text="Range:").grid(row=0, column=0, sticky="w")
        self.range_entry = ttk.Entry(ipf)
        self.range_entry.insert(0, ORIG_DEFAULT_CIDR)
        self.range_entry.grid(row=0, column=1, sticky="ew", padx=4)

        pp = ttk.Frame(frm)
        pp.grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        pp.columnconfigure(0, weight=1)
        pp.columnconfigure(1, weight=1)

        ports_frame = ttk.LabelFrame(pp, text="Ports (one per line, no colon needed)")
        ports_frame.grid(row=0, column=0, sticky="nsew", padx=4, pady=2)
        self.ports_text = tk.Text(ports_frame, width=30, height=8)
        # populate ports from original defaults (strip leading colon for GUI)
        ports_no_colon = [p.lstrip(":") for p in ORIG_PORTS]
        self.ports_text.insert("1.0", "\n".join(ports_no_colon))
        self.ports_text.pack(expand=True, fill="both")

        paths_frame = ttk.LabelFrame(pp, text="Paths (one per line)")
        paths_frame.grid(row=0, column=1, sticky="nsew", padx=4, pady=2)
        self.paths_text = tk.Text(paths_frame, width=50, height=8)
        # populate paths from original defaults
        self.paths_text.insert("1.0", "\n".join(ORIG_PATHS))
        self.paths_text.pack(expand=True, fill="both")

        opts = ttk.Frame(frm)
        opts.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        ttk.Label(opts, text="Multiplier:").grid(row=0, column=0, sticky="w")
        self.multiplier_var = tk.IntVar(value=8)
        ttk.Entry(opts, textvariable=self.multiplier_var, width=6).grid(row=0, column=1, sticky="w", padx=4)

        ttk.Label(opts, text="Max workers cap:").grid(row=0, column=2, sticky="w")
        self.max_workers_var = tk.IntVar(value=200)
        ttk.Entry(opts, textvariable=self.max_workers_var, width=6).grid(row=0, column=3, sticky="w", padx=4)

        ttk.Label(opts, text="Timeout (s):").grid(row=0, column=4, sticky="w")
        self.timeout_var = tk.IntVar(value=5)
        ttk.Entry(opts, textvariable=self.timeout_var, width=6).grid(row=0, column=5, sticky="w", padx=4)

        rndf = ttk.LabelFrame(frm, text="Internet-wide Random Scan (EXPERIMENTAL)")
        rndf.grid(row=3, column=0, sticky="ew", padx=4, pady=4)
        self.internet_var = tk.BooleanVar(value=False)
        self.internet_chk = ttk.Checkbutton(rndf, text="Enable Internet-wide random scan", variable=self.internet_var, command=self._on_internet_toggle)
        self.internet_chk.grid(row=0, column=0, sticky="w", padx=4, pady=2)

        ttk.Label(rndf, text="Random count:").grid(row=0, column=1, sticky="e")
        self.random_count_var = tk.IntVar(value=100)
        self.random_count_entry = ttk.Entry(rndf, textvariable=self.random_count_var, width=8)
        self.random_count_entry.grid(row=0, column=2, sticky="w", padx=4)

        ttk.Label(rndf, text="Seed (optional):").grid(row=0, column=3, sticky="e")
        self.random_seed_var = tk.StringVar(value="")
        ttk.Entry(rndf, textvariable=self.random_seed_var, width=12).grid(row=0, column=4, sticky="w", padx=4)

        ttk.Label(rndf, text="(Will exclude private/reserved ranges automatically)").grid(row=1, column=0, columnspan=5, sticky="w", padx=4)

        ctrl = ttk.Frame(frm)
        ctrl.grid(row=4, column=0, sticky="ew", padx=4, pady=4)
        self.start_btn = ttk.Button(ctrl, text="Start Scan", command=self.start_scan)
        self.start_btn.grid(row=0, column=0, padx=4)
        self.stop_btn = ttk.Button(ctrl, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=4)
        ttk.Button(ctrl, text="Save Log As...", command=self.save_log_as).grid(row=0, column=2, padx=4)
        ttk.Button(ctrl, text="Clear Results", command=self.clear_results).grid(row=0, column=3, padx=4)

        res_frame = ttk.LabelFrame(frm, text="Results (live)")
        res_frame.grid(row=5, column=0, sticky="nsew", padx=4, pady=4)
        frm.rowconfigure(5, weight=1)
        res_frame.columnconfigure(0, weight=1)
        res_frame.rowconfigure(0, weight=1)
        self.results_text = tk.Text(res_frame, wrap="none", height=20)
        self.results_text.grid(row=0, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(res_frame, orient="vertical", command=self.results_text.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        self.results_text.configure(yscrollcommand=vsb.set)

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(frm, textvariable=self.status_var).grid(row=6, column=0, sticky="w", padx=4, pady=(2,4))

        self.log_path = LOG_FILE_DEFAULT
        ensure_log_header(self.log_path)

    def _on_internet_toggle(self):
        enabled = self.internet_var.get()
        if enabled:
            self.range_entry.configure(state="disabled")
        else:
            self.range_entry.configure(state="normal")

    def start_scan(self):
        if self.internet_var.get():
            ok = messagebox.askokcancel(
                "Confirm Internet-wide Scan",
                ("You have enabled INTERNET-WIDE random scanning.\n\n"
                 "Only proceed if you have permission to scan targets and understand the legal/ethical implications.\n\n"
                 "Proceed?"))
            if not ok:
                return

        ports_raw = self.ports_text.get("1.0", "end").strip().splitlines()
        paths_raw = self.paths_text.get("1.0", "end").strip().splitlines()
        ports = [normalize_port(p) for p in ports_raw if p.strip()]
        paths = [p.strip() for p in paths_raw if p.strip()]
        if not ports or not paths:
            messagebox.showerror("Missing configuration", "Please add at least one port and one path.")
            return

        if self.internet_var.get():
            try:
                count = int(self.random_count_var.get())
                if count <= 0:
                    raise ValueError()
            except Exception:
                messagebox.showerror("Invalid count", "Random count must be a positive integer.")
                return
            seed = self.random_seed_var.get() or None
            ip_iter = (str(ip) for ip in random_public_ipv4_generator(count, seed=seed))
        else:
            raw = self.range_entry.get().strip()
            if not raw:
                messagebox.showerror("Missing range", "Please provide an IP range or enable internet-wide random scan.")
                return
            try:
                args = raw.split()
                ip_iter = (str(ip) for ip in parse_ip_range(args, include_all_addresses=False))
            except Exception as e:
                messagebox.showerror("Range parse error", str(e))
                return

        io_mult = max(1, int(self.multiplier_var.get()))
        suggested = determine_thread_count(max_cap=self.max_workers_var.get() or 200, io_multiplier=io_mult, min_threads=4)
        max_workers = min(self.max_workers_var.get() or suggested, 1000)
        timeout = max(1, int(self.timeout_var.get() or 5))

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set("Starting scan...")
        self.stop_event.clear()
        self.results_text.insert("end", f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Starting scan. workers={max_workers}, timeout={timeout}\n")
        self.results_text.see("end")

        ensure_log_header(self.log_path)

        t = threading.Thread(target=self._scan_worker, args=(ip_iter, ports, paths, max_workers, timeout), daemon=True)
        t.start()

    def _scan_worker(self, ip_iter, ports, paths, max_workers, timeout):
        SUBMIT_BUFFER = max_workers * 2
        submitted = 0
        completed = 0
        self.futures = set()

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as exe:
                url_gen = gen_urls_on_the_fly_from_iter(ip_iter, ports, paths)
                for url in url_gen:
                    if self.stop_event.is_set():
                        break
                    fut = exe.submit(fetch, url, timeout=timeout)
                    self.futures.add(fut)
                    submitted += 1

                    if len(self.futures) >= SUBMIT_BUFFER:
                        finished, self.futures = wait(self.futures, return_when=FIRST_COMPLETED)
                        for fut in finished:
                            if self.stop_event.is_set():
                                break
                            try:
                                url_r, status, size, err = fut.result()
                                completed += 1
                                self.result_q.put((url_r, status, size, err))
                                log_result_to(self.log_path, url_r, status, err or (f"{size} bytes" if size else ""))
                            except Exception as e:
                                completed += 1
                                self.result_q.put((None, "FUTURE_EXC", None, str(e)))
                while self.futures and not self.stop_event.is_set():
                    finished, self.futures = wait(self.futures, return_when=FIRST_COMPLETED)
                    for fut in finished:
                        try:
                            url_r, status, size, err = fut.result()
                            completed += 1
                            self.result_q.put((url_r, status, size, err))
                            log_result_to(self.log_path, url_r, status, err or (f"{size} bytes" if size else ""))
                        except Exception as e:
                            completed += 1
                            self.result_q.put((None, "FUTURE_EXC", None, str(e)))
        except Exception as e:
            self.result_q.put((None, "ERROR", None, str(e)))
        finally:
            self.result_q.put(("__DONE__", submitted, completed, None))

    def _poll_results(self):
        try:
            while True:
                item = self.result_q.get_nowait()
                if item[0] == "__DONE__":
                    submitted, completed, _ = item[1], item[2], item[3]
                    self.results_text.insert("end", f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Scan finished. submitted={submitted}, completed={completed}\n")
                    self.results_text.see("end")
                    self.status_var.set("Finished")
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                else:
                    url, status, size, err = item
                    if url is None:
                        self.results_text.insert("end", f"[ERR] {status}: {err}\n")
                    else:
                        if err:
                            self.results_text.insert("end", f"{url} -> {status} ({err})\n")
                        else:
                            self.results_text.insert("end", f"{url} -> {status} ({size} bytes)\n")
                    self.results_text.see("end")
        except queue.Empty:
            pass
        self.root.after(200, self._poll_results)

    def stop_scan(self):
        self.stop_event.set()
        self.status_var.set("Stopping...")
        self.stop_btn.configure(state="disabled")
        self.results_text.insert("end", f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Stop requested. Waiting for in-flight requests to finish...\n")
        self.results_text.see("end")

    def save_log_as(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv"), ("All files","*.*")])
        if path:
            try:
                with _WRITE_LOCK:
                    ensure_log_header(self.log_path)
                    with open(self.log_path, "rb") as src, open(path, "wb") as dst:
                        dst.write(src.read())
                messagebox.showinfo("Saved", f"Log copied to {path}")
            except Exception as e:
                messagebox.showerror("Save failed", str(e))

    def clear_results(self):
        self.results_text.delete("1.0", "end")

def main():
    root = tk.Tk()
    root.geometry("920x700")
    app = ScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

