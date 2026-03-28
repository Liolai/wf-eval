#!/usr/bin/env python3
"""
Web Flow Evaluation Tool - Core Measurement Script (Federico's Request Updated)

Updates for PhD Thesis Requirements:
1. Split Dummy into 'dummy_fixed' and 'dummy_dynamic'.
2. Added 'combined' mode (Fixed Drop + Variable Dummy).
3. Added 'combined_sync' mode (Drop and Dummy increase together).
4. Implemented Batching/Round-Robin execution to average out network delays.
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

_loader_procs = []

def set_loader(ns: str, mode: str, ifname: str, *, 
               fixed_prob=None, 
               dyn_max=None, dyn_min_pps=None, dyn_max_pps=None,
               combined_drop=None, combined_dummy=None):
    global _loader_procs
    
    for proc in _loader_procs:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                proc.wait(timeout=1)
            except Exception:
                try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception: pass
    _loader_procs = [] 
    
    if mode == "off": return
        
    if not LOADER_BIN.exists():
        raise SystemExit("ERROR: build the loader first:  (cd ebpf && make)")
    
    cmds = []

    if mode == "fixed" or mode == "ingress":
        cmds.append(f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode fixed --prob {int(fixed_prob)}")
    elif mode == "dummy_fixed":
        cmds.append(f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode dummy --prob {int(fixed_prob)}")
    elif mode == "dynamic":
        cmds.append(f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode dynamic "
                    f"--max-prob {int(dyn_max)} --min-rate {int(dyn_min_pps)} --max-rate {int(dyn_max_pps)}")
    elif mode == "dummy_dynamic":
        cmds.append(f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode dummy_dynamic "
                    f"--max-prob {int(dyn_max)} --min-rate {int(dyn_min_pps)} --max-rate {int(dyn_max_pps)}")
    elif mode == "combined" or mode == "combined_sync":
        cmd_drop = f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode fixed --prob {int(combined_drop)}"
        cmds.append(cmd_drop)
        cmd_dummy = f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode dummy --prob {int(combined_dummy)}"
        cmds.append(cmd_dummy)
    else:
        raise ValueError(f"Unknown eBPF mode: {mode}")
    
    for cmd in cmds:
        proc = run_in_ns(ns, cmd)
        _loader_procs.append(proc)
        time.sleep(0.5) 
        if proc.poll() is not None:
             raise SystemExit(f"[ERROR] Loader failed to start: {cmd}")

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

    # --- 修复 1: 提前初始化时间变量 ---
    t0 = time.time() 

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
        
        drv = None # 初始化 drv 变量
        try:
            drv = webdriver.Chrome(service=Service(executable_path=cdrv), options=opts)
            drv.set_page_load_timeout(120)
            
            # 可能会在这里崩，但 t0 已经在上面赋值了，所以不会报错
            drv.execute_cdp_cmd('Network.setCacheDisabled', {'cacheDisabled': True})
            drv.execute_cdp_cmd('Network.clearBrowserCache', {})
            
            t0 = time.time() # 真正开始访问前更新 t0
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
            # 这里的 t0 肯定有值了（最差也是函数开头的 time.time()）
            print(f"[ERROR] Navigation failed for {url}: {e}")
            return {"plt_ms": 0, "t_wall_start": t0, "t_wall_end": time.time()}
        finally:
            if drv: 
                try: drv.quit()
                except: pass
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
    
    # --- NEW MODE: combined_sync ---
    parser.add_argument("--mode", 
                        choices=["off","fixed","dynamic","dummy_fixed","dummy_dynamic","combined","combined_sync","ingress"], 
                        required=True)
    
    # --- BATCHING PARAMS ---
    parser.add_argument("--runs-per-level", type=int, default=100, help="Total number of runs per configuration")
    parser.add_argument("--batch-size", type=int, default=20, help="How many runs to do before switching configs (Round-Robin)")
    
    # Levels
    parser.add_argument("--levels", default="0,5,10", help="Probabilities for fixed/dummy modes, or 'drop:dummy' for combined_sync")
    
    # Dynamic params
    parser.add_argument("--dynamic-max-prob", type=int, default=50)
    parser.add_argument("--dynamic-min-pps", type=int, default=1000)
    parser.add_argument("--dynamic-max-pps", type=int, default=100000)
    
    # Combined params
    parser.add_argument("--combined-drop-prob", type=int, default=5)
    
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
    
    # Parse levels
    raw_levels = [x.strip() for x in args.levels.split(",") if x.strip()]
    
    # Calculate batches
    num_batches = max(1, args.runs_per_level // args.batch_size)
    print(f"[preflight] ns={args.ns} mode={args.mode} total_runs={args.runs_per_level} batch_size={args.batch_size} batches={num_batches}")

    urls = [u.strip() for u in open(args.urls) if u.strip() and not u.startswith("#")]
    random.seed(123)

    file_exists = CSV_PATH.exists()
    with open(CSV_PATH, "a" if file_exists else "w", newline="") as f:
        fieldnames = ["mode","level","url","rep","pcap","plt_ms","t_wall_start","t_wall_end",
                      "dyn_max_prob","dyn_min_pps","dyn_max_pps", "extra_param"]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists: w.writeheader()

        # ================== BATCH EXECUTION LOOP ==================
        for batch in range(num_batches):
            print(f"\n=========================================")
            print(f"=== Starting Batch {batch+1}/{num_batches} ===")
            print(f"=========================================\n")
            
            start_rep = batch * args.batch_size + 1
            end_rep = start_rep + args.batch_size

            # --- 0. BASELINE ---
            if args.mode == "off":
                set_loader(args.ns, "off", ifname)
                for rep in range(start_rep, end_rep):
                    random.shuffle(urls)
                    for url in tqdm(urls, desc=f"baseline rep {rep}/{args.runs_per_level}"):
                        tag = f"off_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                        pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                        w.writerow({"mode":"off","level":0,"url":url,"rep":rep,"pcap":pcap,
                                    "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                    "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":"","extra_param":""}); f.flush()

            # --- 1. FIXED STRATEGIES ---
            elif args.mode in ["fixed", "dummy_fixed", "ingress"]:
                for lvl in raw_levels:
                    lvl = int(lvl)
                    set_loader(args.ns, args.mode, ifname, fixed_prob=lvl)
                    for rep in range(start_rep, end_rep):
                        random.shuffle(urls)
                        for url in tqdm(urls, desc=f"{args.mode} {lvl}% rep {rep}/{args.runs_per_level}"):
                            tag = f"{args.mode}_lvl{lvl}_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                            pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                            w.writerow({"mode":args.mode,"level":lvl,"url":url,"rep":rep,"pcap":pcap,
                                        "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                        "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":"","extra_param":""}); f.flush()

            # --- 2. DYNAMIC STRATEGIES ---
            elif args.mode in ["dynamic", "dummy_dynamic"]:
                set_loader(args.ns, args.mode, ifname, dyn_max=args.dynamic_max_prob, 
                           dyn_min_pps=args.dynamic_min_pps, dyn_max_pps=args.dynamic_max_pps)
                for rep in range(start_rep, end_rep):
                    random.shuffle(urls)
                    for url in tqdm(urls, desc=f"{args.mode} rep {rep}/{args.runs_per_level}"):
                        tag = f"{args.mode}_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                        pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                        w.writerow({"mode":args.mode,"level":-1,"url":url,"rep":rep,"pcap":pcap,
                                    "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                    "dyn_max_prob":args.dynamic_max_prob,"dyn_min_pps":args.dynamic_min_pps,"dyn_max_pps":args.dynamic_max_pps,
                                    "extra_param":""}); f.flush()

            # --- 3. COMBINED STRATEGY (Fixed Drop + Varying Dummy) ---
            elif args.mode == "combined":
                drop_lvl = args.combined_drop_prob
                for d_lvl in raw_levels:
                    d_lvl = int(d_lvl)
                    set_loader(args.ns, "combined", ifname, combined_drop=drop_lvl, combined_dummy=d_lvl)
                    for rep in range(start_rep, end_rep):
                        random.shuffle(urls)
                        for url in tqdm(urls, desc=f"Comb(Dr{drop_lvl}/Du{d_lvl}) rep {rep}/{args.runs_per_level}"):
                            tag = f"comb_dr{drop_lvl}_du{d_lvl}_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                            pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                            w.writerow({"mode":"combined","level":d_lvl,"url":url,"rep":rep,"pcap":pcap,
                                        "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                        "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":"",
                                        "extra_param":f"drop={drop_lvl}"}); f.flush()

            # --- 4. COMBINED SYNC STRATEGY (Drop and Dummy increase together) ---
            elif args.mode == "combined_sync":
                for pair_str in raw_levels:
                    if ":" in pair_str:
                        drop_lvl, dummy_lvl = map(int, pair_str.split(":"))
                    else:
                        drop_lvl = dummy_lvl = int(pair_str) # Default to same value if not specified
                        
                    set_loader(args.ns, "combined_sync", ifname, combined_drop=drop_lvl, combined_dummy=dummy_lvl)
                    for rep in range(start_rep, end_rep):
                        random.shuffle(urls)
                        for url in tqdm(urls, desc=f"Sync(Dr{drop_lvl}/Du{dummy_lvl}) rep {rep}/{args.runs_per_level}"):
                            tag = f"sync_dr{drop_lvl}_du{dummy_lvl}_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                            pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                            w.writerow({"mode":"combined_sync","level":dummy_lvl,"url":url,"rep":rep,"pcap":pcap,
                                        "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                        "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":"",
                                        "extra_param":f"drop={drop_lvl}"}); f.flush()
                                        
        # Ensure loader is turned off at the end of the script
        set_loader(args.ns, "off", ifname)

if __name__ == "__main__":
    main()
