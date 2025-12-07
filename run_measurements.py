#!/usr/bin/env python3
"""
Web Flow Evaluation Tool - Core Measurement Script (Federico's Request Updated)

Updates for PhD Thesis Requirements:
1. Split Dummy into 'dummy_fixed' and 'dummy_dynamic'.
2. Added 'combined' mode (Fixed Drop + Variable Dummy).
3. Enhanced CSV logging for complex strategies.
"""

import os, csv, time, shlex, signal, tempfile, random, argparse, atexit, shutil, re, subprocess
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager
from tqdm import tqdm

# -------------------------- Default Configuration --------------------------
NS_DEFAULT = "wfns"
OUT_DIR    = Path("out")
PCAPS_DIR  = OUT_DIR / "pcaps"
CSV_PATH   = OUT_DIR / "nav_metrics.csv"
EBPF_DIR   = Path("ebpf")
LOADER_BIN = EBPF_DIR / "loader"

# -------------------------- Shell Command Utilities ------------------------------
def sh(cmd: str):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def ns_sh(ns: str, cmd: str):
    return sh(f"ip netns exec {shlex.quote(ns)} sh -lc {shlex.quote(cmd)}")

def run_in_ns(ns: str, cmd: str, env=None):
    return subprocess.Popen(f"ip netns exec {shlex.quote(ns)} {cmd}", shell=True, env=env, preexec_fn=os.setsid)

# -------------------------- Namespace & Traffic Control --------------------------
def clean_namespace(ns: str):
    print(f"[INFO] Cleaning namespace {ns}...")
    patterns = ["chrome.*--enable-quic", "chromedriver", "tcpdump.*veth1"]
    for pattern in patterns:
        ns_sh(ns, f"pkill -f '{pattern}' 2>/dev/null || true")
    time.sleep(0.5)
    print(f"[SUCCESS] Namespace {ns} cleaned")

def setup_traffic_control():
    print("[INFO] Setting up traffic control for experiment isolation...")
    wan_if = sh("ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}'").stdout.strip()
    if not wan_if:
        print("[WARNING] Could not detect WAN interface, skipping traffic control")
        return None
    
    print(f"[INFO] Applying traffic control on interface: {wan_if}")
    commands = [
        f"tc qdisc add dev {wan_if} root handle 1: htb default 30",
        f"tc class add dev {wan_if} parent 1: classid 1:1 htb rate 100mbit",
        f"tc class add dev {wan_if} parent 1:1 classid 1:10 htb rate 90mbit ceil 95mbit",  
        f"tc class add dev {wan_if} parent 1:1 classid 1:30 htb rate 10mbit ceil 20mbit",  
        f"tc filter add dev {wan_if} parent 1: protocol ip prio 1 u32 match ip src 10.200.0.0/24 classid 1:10",
        f"tc filter add dev {wan_if} parent 1: protocol ip prio 2 u32 match ip src 0.0.0.0/0 classid 1:30"
    ]
    for cmd in commands:
        result = sh(f"sudo {cmd}")
        if result.returncode != 0:
            print(f"[ERROR] Traffic control setup failed: {cmd}")
            cleanup_traffic_control()
            return None
    print("[SUCCESS] Traffic control active")
    return wan_if

def cleanup_traffic_control():
    wan_if = sh("ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}'").stdout.strip()
    if wan_if:
        print(f"[INFO] Removing traffic control from {wan_if}")
        sh(f"sudo tc qdisc del dev {wan_if} root 2>/dev/null || true")
        print("[SUCCESS] Traffic control removed")

# -------------------------- Chrome Management ----------------------------
def pick_chrome_binary():
    for p in ("/usr/bin/google-chrome","/usr/bin/google-chrome-stable","/usr/bin/chromium",
              "/usr/lib/chromium-browser/chromium-browser","/usr/bin/chromium-browser","/snap/bin/chromium"):
        if os.path.exists(p) and os.access(p, os.X_OK):
            try:
                if "/snap/" in os.path.realpath(p): continue
            except Exception: pass
            return p
    return "/snap/bin/chromium"

def get_chrome_major(ns: str, chrome_bin: str):
    out = ns_sh(ns, f"{shlex.quote(chrome_bin)} --version || true").stdout.strip()
    m = re.search(r"\b(\d+)\.", out)
    return int(m.group(1)) if m else None

def find_chromedriver_for_major(major: int):
    for p in ("/usr/bin/chromedriver","/usr/lib/chromium-browser/chromedriver",
              "/usr/lib/chromium/chromedriver","/usr/local/bin/chromedriver"):
        if os.path.exists(p) and os.access(p, os.X_OK):
            try:
                out = subprocess.run([p,"--version"], capture_output=True, text=True).stdout
                m = re.search(r"\b(\d+)\.", out)
                if int(m.group(1)) == major: return p
            except Exception: pass
    return None

@contextmanager
def ns_wrapper(target_bin: str, ns: str):
    fd, path = tempfile.mkstemp(prefix="nswrap-", suffix=".sh")
    try:
        os.write(fd, f"#!/bin/sh\nexec ip netns exec {shlex.quote(ns)} {shlex.quote(target_bin)} \"$@\"\n".encode())
        os.fsync(fd); os.fchmod(fd, 0o755)
    finally:
        os.close(fd)
    try:
        yield path
    finally:
        try: os.unlink(path)
        except Exception: pass

# -------------------------- Firewall & Loader ----------------------
def quic_only_install(ns: str):
    script = r"""
add table inet quiconly 2>/dev/null
add chain inet quiconly out { type filter hook output priority 0; policy accept; } 2>/dev/null
add rule inet quiconly out udp dport 443 accept 2>/dev/null
add rule inet quiconly out tcp dport 443 reject 2>/dev/null
"""
    ns_sh(ns, "nft -f - <<'EOF'\n" + script + "EOF")

def quic_only_uninstall(ns: str):
    ns_sh(ns, "nft delete table inet quiconly 2>/dev/null || true")

_loader_proc = None

def set_loader(ns: str, mode: str, ifname: str, *, 
               fixed_prob=None, 
               dyn_max=None, dyn_min_pps=None, dyn_max_pps=None,
               combined_drop=None, combined_dummy=None):
    global _loader_proc
    
    # Stop existing loader
    if _loader_proc and _loader_proc.poll() is None:
        try:
            os.killpg(os.getpgid(_loader_proc.pid), signal.SIGINT)
            _loader_proc.wait(timeout=3)
        except Exception:
            try: os.killpg(os.getpgid(_loader_proc.pid), signal.SIGTERM)
            except Exception: pass
    _loader_proc = None
    
    if mode == "off": return
        
    if not LOADER_BIN.exists():
        raise SystemExit("ERROR: build the loader first:  (cd ebpf && make)")
    
    # --- UPDATED LOGIC FOR ALL MODES (FEDERICO'S REQUESTS) ---
    
    # 1. FIXED DROP / INGRESS
    if mode == "fixed" or mode == "ingress":
        cmd = f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode fixed --prob {int(fixed_prob)}"
    
    # 2. DUMMY FIXED (Renamed from 'dummy' to be explicit)
    elif mode == "dummy_fixed":
        cmd = f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode dummy --prob {int(fixed_prob)}"
    
    # 3. DYNAMIC DROP
    elif mode == "dynamic":
        cmd = (f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode dynamic "
               f"--max-prob {int(dyn_max)} --min-rate {int(dyn_min_pps)} --max-rate {int(dyn_max_pps)}")

    # 4. DUMMY DYNAMIC (New Request)
    # Assumption: Loader accepts '--mode dummy_dynamic' with same rate params
    elif mode == "dummy_dynamic":
        cmd = (f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode dummy_dynamic "
               f"--max-prob {int(dyn_max)} --min-rate {int(dyn_min_pps)} --max-rate {int(dyn_max_pps)}")

    # 5. COMBINED STRATEGY (New Request: Drop + Dummy)
    # Assumption: Loader accepts '--mode combined --prob X --dummy-prob Y'
    elif mode == "combined":
        cmd = (f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode combined "
               f"--prob {int(combined_drop)} --dummy-prob {int(combined_dummy)}")
        
    else:
        raise ValueError(f"Unknown eBPF mode: {mode}")
    
    _loader_proc = run_in_ns(ns, cmd)
    time.sleep(3)  
    if _loader_proc.poll() is not None:
        raise SystemExit(f"[ERROR] Loader process failed to start (exit code: {_loader_proc.poll()}). Check if your C loader supports mode '{mode}'.")

atexit.register(lambda: set_loader(NS_DEFAULT, "off", "lo"))

# -------------------------- Network Utils & Measurement -----------------------
def autodetect_iface(ns: str):
    p = ns_sh(ns, "ip -o -4 route show default | awk '{print $5}'")
    if p.returncode == 0 and p.stdout.strip(): return p.stdout.strip()
    p = ns_sh(ns, "ip -o link show | awk -F': ' '$2!~/lo/ {print $2; exit}'")
    return p.stdout.strip() or "eth0"

def measure_nav(ns: str, chrome_bin: str, url: str, headless: bool):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    major = get_chrome_major(ns, chrome_bin)
    if not major: raise SystemExit(f"Chrome not found in {ns}")
    cdrv = find_chromedriver_for_major(major)
    if not cdrv: raise SystemExit(f"chromedriver {major}.x not found")

    with ns_wrapper(chrome_bin, ns) as chrome_in_ns:
        opts = Options()
        for a in ("--no-first-run","--disable-extensions","--disable-background-networking",
                  "--disable-sync","--incognito","--disk-cache-size=1",
                  "--disable-application-cache","--disable-back-forward-cache",
                  "--disable-background-timer-throttling","--disable-renderer-backgrounding",
                  "--disable-features=TranslateUI,BlinkGenPropertyTrees",
                  "--enable-quic","--enable-features=UseDnsHttpsSvcb,UseDnsHttpsSvcbAlpn",
                  "--no-sandbox","--disable-dev-shm-usage","--remote-debugging-pipe"):
            opts.add_argument(a)
            
        if headless:
            opts.add_argument("--headless=new")
            opts.add_argument("--hide-scrollbars") 
            opts.add_argument("--disable-gpu")
            
        profile = tempfile.mkdtemp(prefix="chrome-prof-")
        opts.add_argument(f"--user-data-dir={profile}")
        opts.binary_location = chrome_in_ns
        
        drv = webdriver.Chrome(service=Service(executable_path=cdrv), options=opts)

        try:
            drv.set_page_load_timeout(120)
            drv.execute_cdp_cmd('Network.setCacheDisabled', {'cacheDisabled': True})
            drv.execute_cdp_cmd('Network.clearBrowserCache', {})
            
            t0 = time.time()
            drv.get(url)
            
            for _ in range(450):
                if drv.execute_script("return document.readyState") == "complete": break
                time.sleep(0.1)
            
            nav = drv.execute_script("return performance.getEntriesByType('navigation')[0] || {}")
            plt_ms = (nav.get("loadEventEnd", 0) - nav.get("startTime", 0)) or 0
            time.sleep(5)
            
            return {"plt_ms": plt_ms, "t_wall_start": t0, "t_wall_end": time.time()}
            
        except KeyboardInterrupt:
            print(f"[INFO] Navigation interrupted for {url}")
            return {"plt_ms": 0, "t_wall_start": t0, "t_wall_end": time.time()}
        except Exception as e:
            print(f"[ERROR] Navigation failed for {url}: {e}")
            return {"plt_ms": 0, "t_wall_start": t0, "t_wall_end": time.time()}
        finally:
            drv.quit()
            shutil.rmtree(profile, ignore_errors=True)

@contextmanager
def tcpdump_veth1(ns: str, outfile: Path, bpf: str):
    proc = run_in_ns(ns, f"tcpdump -i veth1 -w {shlex.quote(str(outfile))} -U -n {shlex.quote(bpf)}")
    time.sleep(0.6)
    try: yield
    finally:
        try: os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        except Exception: pass
        try: proc.wait(timeout=5)
        except Exception: pass

def capture_one(ns: str, url: str, tag: str, headless: bool, chrome_bin: str):
    pcap = PCAPS_DIR / f"{tag}.pcap"
    nav = {}
    with tcpdump_veth1(ns, pcap, "udp and port 443"):
        nav = measure_nav(ns, chrome_bin, url, headless)

    try:
        ci = ns_sh(ns, f"capinfos -c {shlex.quote(str(pcap))} 2>/dev/null | awk -F': ' '/Number of packets/ {{print $2}}'").stdout.strip()
        pkt = int(ci) if ci.isdigit() else (pcap.stat().st_size > 24)
    except Exception:
        pkt = (pcap.stat().st_size > 24)

    if not pkt: print(f"[warn] empty pcap for {url}")
    return str(pcap), nav or {"plt_ms":0,"t_wall_start":0,"t_wall_end":0}

# -------------------------- Main Execution ---------------------------------------
def main():
    parser = argparse.ArgumentParser(description="QUIC WF eval runner - Updated for Thesis")
    parser.add_argument("--ns", default=NS_DEFAULT)
    parser.add_argument("--urls", default="urls.txt")
    
    # --- UPDATED CHOICES: Added 'dummy_fixed', 'dummy_dynamic', 'combined' ---
    parser.add_argument("--mode", 
                        choices=["off","fixed","dynamic","dummy_fixed","dummy_dynamic","combined","ingress"], 
                        required=True)
    
    parser.add_argument("--levels", default="0,1,2,5,10", help="Probabilities for fixed/dummy/ingress modes")
    parser.add_argument("--runs-per-level", type=int, default=10)
    
    # Dynamic params
    parser.add_argument("--dynamic-max-prob", type=int, default=50)
    parser.add_argument("--dynamic-min-pps", type=int, default=1000)
    parser.add_argument("--dynamic-max-pps", type=int, default=100000)
    
    # Combined params (New)
    parser.add_argument("--combined-drop-prob", type=int, default=5, 
                        help="The fixed DROP probability used in 'combined' mode (Federico suggests low, e.g. 5)")
    
    parser.add_argument("--headless", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--quic-only", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--traffic-control", action=argparse.BooleanOptionalAction, default=True)
    
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    PCAPS_DIR.mkdir(parents=True, exist_ok=True)

    test_ns = subprocess.run(["ip", "netns", "exec", args.ns, "true"], capture_output=True)
    if test_ns.returncode != 0:
        raise SystemExit(f"Permission denied or namespace '{args.ns}' missing.")

    chrome = pick_chrome_binary()
    if args.quic_only:
        quic_only_install(args.ns)
        atexit.register(lambda: quic_only_uninstall(args.ns))

    clean_namespace(args.ns)
    if args.traffic_control:
        if setup_traffic_control():
            atexit.register(cleanup_traffic_control)
            
    ifname = autodetect_iface(args.ns)
    print(f"[preflight] ns={args.ns} if={ifname} chrome={chrome} mode={args.mode}")

    urls = [u.strip() for u in open(args.urls) if u.strip() and not u.startswith("#")]
    random.seed(123)

    file_exists = CSV_PATH.exists()
    # Updated CSV headers to include 'extra_param' for combined drop rate
    with open(CSV_PATH, "a" if file_exists else "w", newline="") as f:
        fieldnames = ["mode","level","url","rep","pcap","plt_ms","t_wall_start","t_wall_end",
                      "dyn_max_prob","dyn_min_pps","dyn_max_pps", "extra_param"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists: w.writeheader()

        # --- 0. BASELINE ---
        if args.mode == "off":
            print("[INFO] Starting baseline (off)")
            set_loader(args.ns, "off", ifname)
            for rep in range(1, args.runs_per_level+1):
                random.shuffle(urls)
                for url in tqdm(urls, desc=f"baseline {rep}/{args.runs_per_level}"):
                    tag = f"off_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                    pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                    w.writerow({"mode":"off","level":0,"url":url,"rep":rep,"pcap":pcap,
                                "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":"","extra_param":""}); f.flush()

        # --- 1. FIXED RATE STRATEGIES (DROP, DUMMY-FIXED, INGRESS) ---
        elif args.mode in ["fixed", "dummy_fixed", "ingress"]:
            levels = [int(x) for x in args.levels.split(",") if x.strip()]
            for lvl in levels:
                print(f"[INFO] Starting {args.mode} mode at level {lvl}%")
                
                # Map 'dummy_fixed' argument to 'dummy' logic if needed, but passing exact mode string to set_loader
                set_loader(args.ns, args.mode, ifname, fixed_prob=lvl)
                
                for rep in range(1, args.runs_per_level+1):
                    random.shuffle(urls)
                    for url in tqdm(urls, desc=f"{args.mode} {lvl}% rep {rep}/{args.runs_per_level}"):
                        tag = f"{args.mode}_lvl{lvl}_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                        pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                        w.writerow({"mode":args.mode,"level":lvl,"url":url,"rep":rep,"pcap":pcap,
                                    "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                    "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":"","extra_param":""}); f.flush()
            set_loader(args.ns, "off", ifname)

        # --- 2. DYNAMIC STRATEGIES (DROP, DUMMY-DYNAMIC) ---
        elif args.mode in ["dynamic", "dummy_dynamic"]:
            set_loader(args.ns, args.mode, ifname, dyn_max=args.dynamic_max_prob, 
                       dyn_min_pps=args.dynamic_min_pps, dyn_max_pps=args.dynamic_max_pps)
            
            for rep in range(1, args.runs_per_level+1):
                random.shuffle(urls)
                for url in tqdm(urls, desc=f"{args.mode} rep {rep}/{args.runs_per_level}"):
                    tag = f"{args.mode}_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                    pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                    w.writerow({"mode":args.mode,"level":-1,"url":url,"rep":rep,"pcap":pcap,
                                "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                "dyn_max_prob":args.dynamic_max_prob,"dyn_min_pps":args.dynamic_min_pps,"dyn_max_pps":args.dynamic_max_pps,
                                "extra_param":""}); f.flush()
            set_loader(args.ns, "off", ifname)

        # --- 3. COMBINED STRATEGY (DROP + DUMMY) ---
        elif args.mode == "combined":
            # Here, 'levels' from args controls the DUMMY PROBABILITY
            # 'combined-drop-prob' controls the DROP PROBABILITY (Fixed)
            dummy_levels = [int(x) for x in args.levels.split(",") if x.strip()]
            drop_lvl = args.combined_drop_prob
            
            for d_lvl in dummy_levels:
                print(f"[INFO] Starting Combined Mode: Drop={drop_lvl}%, Dummy={d_lvl}%")
                set_loader(args.ns, "combined", ifname, combined_drop=drop_lvl, combined_dummy=d_lvl)
                
                for rep in range(1, args.runs_per_level+1):
                    random.shuffle(urls)
                    for url in tqdm(urls, desc=f"Comb(Dr{drop_lvl}/Du{d_lvl}) rep {rep}/{args.runs_per_level}"):
                        tag = f"comb_dr{drop_lvl}_du{d_lvl}_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                        pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                        
                        # Record: level = dummy level, extra_param = drop level
                        w.writerow({"mode":"combined","level":d_lvl,"url":url,"rep":rep,"pcap":pcap,
                                    "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                    "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":"",
                                    "extra_param":f"drop={drop_lvl}"}); f.flush()
            set_loader(args.ns, "off", ifname)

if __name__ == "__main__":
    main()
