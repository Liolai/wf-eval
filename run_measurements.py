#!/usr/bin/env python3
"""
Web Flow Evaluation Tool - Core Measurement Script

This script performs automated web performance measurements with controlled packet dropping
using eBPF programs, Selenium WebDriver, and network namespaces for traffic isolation.

The measurement process:
1. Sets up isolated network environment using network namespaces
2. Applies traffic control to prevent host interference 
3. Optionally installs QUIC-only firewall rules to force QUIC protocol usage
4. Runs eBPF packet dropper with configurable drop rates (fixed/dynamic/off)
5. Uses Selenium to navigate websites while capturing UDP/QUIC traffic
6. Records performance metrics (page load time, wall clock time)
7. Saves packet captures for later analysis

Modes:
- 'off': Baseline measurements without packet dropping
- 'fixed': Static packet drop rates (0-20%)  
- 'dynamic': Variable drop rates based on traffic patterns
"""

import os, csv, time, shlex, signal, tempfile, random, argparse, atexit, shutil, re, subprocess
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager
from tqdm import tqdm

# -------------------------- Default Configuration --------------------------
# These constants define the default setup for the evaluation environment
NS_DEFAULT = "wfns"         # Default network namespace name for traffic isolation
OUT_DIR    = Path("out")    # Output directory for all measurement results
PCAPS_DIR  = OUT_DIR / "pcaps"  # Subdirectory for packet capture files
CSV_PATH   = OUT_DIR / "nav_metrics.csv"  # Main results file with navigation metrics
EBPF_DIR   = Path("ebpf")   # Directory containing eBPF programs and loader
LOADER_BIN = EBPF_DIR / "loader"  # Compiled eBPF loader binary

# -------------------------- Shell Command Utilities ------------------------------
# These functions provide safe ways to execute shell commands in different contexts
def sh(cmd: str):
    """
    Execute a shell command in the host environment
    
    Args:
        cmd: Shell command string to execute
        
    Returns:
        CompletedProcess with stdout, stderr, and return code
        
    Used for: Host-level operations like traffic control setup
    """
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def ns_sh(ns: str, cmd: str):
    """
    Execute a shell command inside a specific network namespace
    
    Args:
        ns: Network namespace name (e.g., "wfns")
        cmd: Shell command to execute inside the namespace
        
    Returns:
        CompletedProcess with command results
        
    Used for: Namespace-specific operations like ping tests, process cleanup
    """
    return sh(f"ip netns exec {shlex.quote(ns)} sh -lc {shlex.quote(cmd)}")

def run_in_ns(ns: str, cmd: str, env=None):
    """
    Start a background process inside a network namespace
    
    Args:
        ns: Network namespace name
        cmd: Command to run as background process
        env: Optional environment variables
        
    Returns:
        Popen object for process management
        
    Used for: Long-running processes like tcpdump, eBPF loader, Chrome browser
    """
    return subprocess.Popen(f"ip netns exec {shlex.quote(ns)} {cmd}", shell=True, env=env, preexec_fn=os.setsid)

# -------------------------- Network Namespace Management --------------------------
# Functions for cleaning and preparing the isolated network environment
def clean_namespace(ns: str):
    """
    Clean the namespace from experiment processes (lightweight with traffic control active)
    
    This function removes any lingering processes from previous experiments to ensure
    a clean testing environment. It specifically targets:
    - Chrome browser instances running with QUIC enabled
    - ChromeDriver processes from Selenium
    - tcpdump processes capturing on veth1 interface
    
    Args:
        ns: Network namespace name to clean
        
    Why this is needed:
    - Previous experiments may leave background processes running
    - These processes can interfere with new measurements
    - Network resources need to be freed for accurate testing
    """
    print(f"[INFO] Cleaning namespace {ns}...")
    
    # Essential patterns for experiment processes (simplified with TC active)
    # These patterns target the specific processes we start during experiments
    patterns = [
        "chrome.*--enable-quic",  # Chrome experiments with QUIC protocol enabled
        "chromedriver",           # Selenium WebDriver automation processes  
        "tcpdump.*veth1"         # Previous packet capture sessions on virtual interface
    ]
    
    # Quick and safe cleanup - use pkill to terminate matching processes
    # The '|| true' ensures the script continues even if no processes are found
    for pattern in patterns:
        ns_sh(ns, f"pkill -f '{pattern}' 2>/dev/null || true")
    
    # Short pause for cleanup - allow processes to terminate gracefully
    time.sleep(0.5)
    print(f"[SUCCESS] Namespace {ns} cleaned")

# -------------------------- Traffic Control (Bandwidth Limiting) --------------------------
# These functions implement Quality of Service (QoS) to isolate experiment traffic
# These functions implement Quality of Service (QoS) to isolate experiment traffic

def setup_traffic_control():
    """
    Setup traffic control to isolate experiment traffic from host interference
    
    This function creates a hierarchical traffic control (TC) system that:
    1. Gives priority to namespace traffic (90% bandwidth)
    2. Limits host traffic to prevent interference (10% bandwidth)
    3. Uses HTB (Hierarchical Token Bucket) qdisc for fair queuing
    
    Why this is critical:
    - Host system background traffic can affect measurement accuracy
    - Other applications downloading/uploading can create noise
    - We need consistent baseline conditions for reproducible results
    
    Returns:
        str: WAN interface name if successful, None if failed
    """
    print("[INFO] Setting up traffic control for experiment isolation...")
    
    # Find main WAN interface - the interface used for internet connectivity
    # This is where we need to apply traffic shaping to control bandwidth usage
    wan_if = sh("ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}'").stdout.strip()
    if not wan_if:
        print("[WARNING] Could not detect WAN interface, skipping traffic control")
        return None
    
    print(f"[INFO] Applying traffic control on interface: {wan_if}")
    
    # Create traffic shaping hierarchy using HTB (Hierarchical Token Bucket)
    # This creates a two-tier system:
    # - Priority class for namespace traffic (90% bandwidth allocation)
    # - Limited class for host traffic (10% bandwidth allocation)
    commands = [
        # Root qdisc - establishes the traffic control framework
        f"tc qdisc add dev {wan_if} root handle 1: htb default 30",
        
        # Root class - defines total available bandwidth (100 Mbit baseline)
        f"tc class add dev {wan_if} parent 1: classid 1:1 htb rate 100mbit",
        
        # High priority class for namespace traffic (experiment data)
        # Rate: 90mbit guaranteed, ceil: 95mbit maximum burst
        f"tc class add dev {wan_if} parent 1:1 classid 1:10 htb rate 90mbit ceil 95mbit",  
        
        # Limited class for host traffic (background applications)
        # Rate: 10mbit guaranteed, ceil: 20mbit maximum burst  
        f"tc class add dev {wan_if} parent 1:1 classid 1:30 htb rate 10mbit ceil 20mbit",  
        
        # Filter rules to classify traffic:
        # Traffic from namespace subnet (10.200.0.0/24) -> high priority class
        f"tc filter add dev {wan_if} parent 1: protocol ip prio 1 u32 match ip src 10.200.0.0/24 classid 1:10",
        
        # Everything else (host traffic) -> limited class (default via 'default 30')
        f"tc filter add dev {wan_if} parent 1: protocol ip prio 2 u32 match ip src 0.0.0.0/0 classid 1:30"
    ]
    
    # Apply each traffic control command
    for cmd in commands:
        result = sh(f"sudo {cmd}")
        if result.returncode != 0:
            print(f"[ERROR] Traffic control setup failed: {cmd}")
            print(f"[ERROR] {result.stderr}")
            cleanup_traffic_control()  # Clean up partial configuration
            return None
    
    print("[SUCCESS] Traffic control active - experiment traffic isolated from host")
    return wan_if

def cleanup_traffic_control():
    """
    Remove traffic control rules
    
    This function cleans up the traffic shaping configuration when experiments
    are finished or if setup fails. It removes the entire qdisc hierarchy.
    
    Why cleanup is important:
    - Traffic control rules persist until explicitly removed
    - Leftover rules can affect normal system network performance
    - Clean slate ensures no interference with future runs
    """
    wan_if = sh("ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}'").stdout.strip()
    if wan_if:
        print(f"[INFO] Removing traffic control from {wan_if}")
        # Delete root qdisc - this removes the entire hierarchy
        sh(f"sudo tc qdisc del dev {wan_if} root 2>/dev/null || true")
        print("[SUCCESS] Traffic control removed")

# -------------------------- Chrome Browser Detection and Management ----------------------------
# Functions for finding compatible Chrome browser and ChromeDriver versions
# Functions for finding compatible Chrome browser and ChromeDriver versions

def pick_chrome_binary():
    """
    Automatically detect and select the best available Chrome browser binary
    
    This function searches common installation paths for Chrome/Chromium browsers
    and selects the most suitable one for our experiments.
    
    Priority order:
    1. Google Chrome stable (preferred for consistent behavior)
    2. Chromium browser (open-source alternative)
    3. Snap packages (avoided when possible due to sandboxing issues)
    
    Returns:
        str: Path to the selected Chrome binary
        
    Why version matters:
    - Different Chrome versions have varying QUIC protocol support
    - We need a version that supports the latest QUIC features
    - ChromeDriver version must match Chrome major version
    """
    # List of common Chrome installation paths, in priority order
    for p in ("/usr/bin/google-chrome","/usr/bin/google-chrome-stable","/usr/bin/chromium",
              "/usr/lib/chromium-browser/chromium-browser","/usr/bin/chromium-browser","/snap/bin/chromium"):
        if os.path.exists(p) and os.access(p, os.X_OK):
            try:
                # Avoid snap packages when possible due to additional sandboxing
                # that can interfere with network namespace operation
                if "/snap/" in os.path.realpath(p):  
                    continue
            except Exception:
                pass
            return p
    # Fallback to snap if no other option available
    return "/snap/bin/chromium"

def get_chrome_major(ns: str, chrome_bin: str):
    """
    Extract the major version number from Chrome browser
    
    Args:
        ns: Network namespace to run Chrome in
        chrome_bin: Path to Chrome binary
        
    Returns:
        int: Major version number (e.g., 120 for Chrome 120.x.x.x)
        
    Why this is needed:
    - ChromeDriver version must match Chrome major version exactly
    - Different versions have different QUIC protocol capabilities
    - Version mismatch causes WebDriver to fail completely
    """
    out = ns_sh(ns, f"{shlex.quote(chrome_bin)} --version || true").stdout.strip()
    m = re.search(r"\b(\d+)\.", out)
    return int(m.group(1)) if m else None

def find_chromedriver_for_major(major: int):
    """
    Find ChromeDriver binary matching the specified Chrome major version
    
    Args:
        major: Chrome major version number
        
    Returns:
        str: Path to compatible ChromeDriver, or None if not found
        
    Critical compatibility requirement:
    - ChromeDriver 120.x must be used with Chrome 120.x
    - Version mismatch results in "This version of ChromeDriver only supports..." error
    - Multiple ChromeDriver versions may be installed in different locations
    """
    # Search common ChromeDriver installation paths
    for p in ("/usr/bin/chromedriver","/usr/lib/chromium-browser/chromedriver",
              "/usr/lib/chromium/chromedriver","/usr/local/bin/chromedriver"):
        if os.path.exists(p) and os.access(p, os.X_OK):
            try:
                # Query ChromeDriver version and check for compatibility
                out = subprocess.run([p,"--version"], capture_output=True, text=True).stdout
                m = re.search(r"\b(\d+)\.", out)
                if int(m.group(1)) == major:
                    return p
            except Exception:
                pass
    return None

@contextmanager
def ns_wrapper(target_bin: str, ns: str):
    """
    Create a temporary wrapper script to run Chrome inside a network namespace
    
    This context manager creates a shell script that:
    1. Executes 'ip netns exec' to enter the namespace
    2. Runs the target binary (Chrome) with all arguments passed through
    3. Cleans up the wrapper script when done
    
    Args:
        target_bin: Path to Chrome binary
        ns: Network namespace name
        
    Yields:
        str: Path to the temporary wrapper script
        
    Why this is necessary:
    - Selenium WebDriver expects a direct binary path
    - We need Chrome to run inside the network namespace
    - The wrapper transparently bridges this gap
    """
    # Create temporary file for wrapper script
    fd, path = tempfile.mkstemp(prefix="nswrap-", suffix=".sh")
    try:
        # Write wrapper script that executes Chrome in namespace
        os.write(fd, f"#!/bin/sh\nexec ip netns exec {shlex.quote(ns)} {shlex.quote(target_bin)} \"$@\"\n".encode())
        os.fsync(fd); os.fchmod(fd, 0o755)  # Make executable
    finally:
        os.close(fd)
    try:
        yield path
    finally:
        # Clean up temporary wrapper script
        try: os.unlink(path)
        except Exception: pass

# -------------------------- QUIC-Only Firewall Rules (Optional) ----------------------
# Functions to force QUIC protocol usage by blocking TCP/443 connections
# Functions to force QUIC protocol usage by blocking TCP/443 connections

def quic_only_install(ns: str):
    """
    Install firewall rules to force QUIC protocol usage
    
    This function uses nftables (netfilter) to:
    1. Allow UDP traffic on port 443 (QUIC protocol)
    2. Block TCP traffic on port 443 (HTTPS over TCP)
    
    Args:
        ns: Network namespace to apply rules in
        
    Why force QUIC-only:
    - Ensures we're measuring QUIC performance specifically
    - Websites often fall back to TCP if QUIC fails
    - Packet dropping affects QUIC differently than TCP
    - Provides consistent protocol usage across measurements
    
    Technical details:
    - Creates 'quiconly' table with output chain
    - UDP/443 packets are accepted (QUIC traffic)
    - TCP/443 packets are rejected (forces QUIC usage)
    """
    script = r"""
add table inet quiconly 2>/dev/null
add chain inet quiconly out { type filter hook output priority 0; policy accept; } 2>/dev/null
add rule inet quiconly out udp dport 443 accept 2>/dev/null
add rule inet quiconly out tcp dport 443 reject 2>/dev/null
"""
    ns_sh(ns, "nft -f - <<'EOF'\n" + script + "EOF")

def quic_only_uninstall(ns: str):
    """
    Remove QUIC-only firewall rules
    
    Args:
        ns: Network namespace to clean rules from
        
    This removes the entire 'quiconly' nftables table, restoring
    normal TCP/UDP traffic flow to port 443.
    """
    ns_sh(ns, "nft delete table inet quiconly 2>/dev/null || true")

# -------------------------- eBPF Packet Dropper Management --------------------------------
# Functions for controlling the eBPF program that drops UDP packets at specified rates
# Functions for controlling the eBPF program that drops UDP packets at specified rates

_loader_proc = None  # Global variable to track the eBPF loader process

def set_loader(ns: str, mode: str, ifname: str, *, fixed_prob=None, dyn_max=None, dyn_min_pps=None, dyn_max_pps=None):
    """
    Manages start/stop of the eBPF packet dropper based on experiment mode
    
    This function controls the eBPF program that simulates network packet loss
    by dropping UDP packets (targeting QUIC traffic) at specified rates.
    
    Args:
        ns: Network namespace to run loader in
        mode: Operation mode ('off', 'fixed', 'dynamic')
        ifname: Network interface name to attach eBPF program to
        fixed_prob: Percentage drop rate for 'fixed' mode (0-100)
        dyn_max: Maximum drop percentage for 'dynamic' mode
        dyn_min_pps: Minimum packets/second threshold for dynamic dropping
        dyn_max_pps: Maximum packets/second threshold for dynamic dropping
        
    Modes explained:
    - 'off': No packet dropping (baseline measurements)
    - 'fixed': Constant drop rate throughout the measurement
    - 'dynamic': Variable drop rate based on current traffic volume
    
    Why eBPF for packet dropping:
    - Kernel-level efficiency (no userspace context switching)
    - Precise timing and minimal overhead
    - Can target specific packet types (UDP/QUIC)
    - Real-time traffic rate monitoring for dynamic mode
    """
    global _loader_proc
    
    # Stop any currently running loader process
    if _loader_proc and _loader_proc.poll() is None:
        try:
            # Send SIGINT first for graceful shutdown
            os.killpg(os.getpgid(_loader_proc.pid), signal.SIGINT)
            _loader_proc.wait(timeout=3)
        except Exception:
            try: 
                # Force termination if graceful shutdown fails
                os.killpg(os.getpgid(_loader_proc.pid), signal.SIGTERM)
            except Exception: 
                pass
    _loader_proc = None
    
    # If mode is 'off', just stop and don't start a new loader
    if mode == "off":
        return
        
    # Verify eBPF loader binary exists
    if not LOADER_BIN.exists():
        raise SystemExit("ERROR: build the loader first:  (cd ebpf && make)")
    
    # Construct command line for eBPF loader based on mode
    if mode == "fixed":
        # Fixed mode: constant drop probability throughout measurement
        cmd = f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode fixed --prob {int(fixed_prob)}"
    elif mode == "dynamic":
        # Dynamic mode: drop rate varies based on current packet rate
        # Higher traffic = higher drop rate (simulates congestion)
        cmd = (f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode dynamic "
               f"--max-prob {int(dyn_max)} --min-rate {int(dyn_min_pps)} --max-rate {int(dyn_max_pps)}")
    else:
        raise ValueError(f"Unknown eBPF mode: {mode}")
    
    # Start the eBPF loader process in the network namespace
    _loader_proc = run_in_ns(ns, cmd)
    
    # Give time for eBPF program to attach to interface and initialize
    time.sleep(3)  
    
    # Verify that loader process started successfully
    if _loader_proc.poll() is not None:
        raise SystemExit(f"[ERROR] Loader process failed to start (exit code: {_loader_proc.poll()})")

# Register cleanup function to stop eBPF loader on script exit
atexit.register(lambda: set_loader(NS_DEFAULT, "off", "lo"))

# -------------------------- Network Diagnostics and Interface Detection --------------------------------
# Functions for network troubleshooting and automatic interface discovery
# Functions for network troubleshooting and automatic interface discovery

def autodetect_iface(ns: str):
    """
    Automatically detect the primary network interface in the namespace
    
    Args:
        ns: Network namespace name
        
    Returns:
        str: Interface name (e.g., 'veth1', 'eth0')
        
    Detection strategy:
    1. First try to find default route interface (most reliable)
    2. Fall back to first non-loopback interface
    3. Default to 'eth0' if nothing found
    
    Why auto-detection is needed:
    - Different namespace setups may use different interface names
    - The eBPF program needs to attach to the correct interface
    - Manual configuration is error-prone
    """
    # Try to get interface from default route (most reliable method)
    p = ns_sh(ns, "ip -o -4 route show default | awk '{print $5}'")
    if p.returncode == 0 and p.stdout.strip():
        return p.stdout.strip()
    
    # Fallback: get first non-loopback interface
    p = ns_sh(ns, "ip -o link show | awk -F': ' '$2!~/lo/ {print $2; exit}'")
    return p.stdout.strip() or "eth0"

def ns_has_udp443(ns: str):
    """
    Check if namespace has active UDP connections on port 443 (QUIC)
    
    Args:
        ns: Network namespace name
        
    Returns:
        bool: True if UDP/443 connections exist
        
    Used for: Verifying that QUIC traffic is actually being generated
    """
    return bool(ns_sh(ns, "ss -u -n | awk '$5 ~ /:443$/'").stdout.strip())

def ns_diag(ns: str):
    """
    Print comprehensive network diagnostics for the namespace
    
    Args:
        ns: Network namespace name
        
    This function outputs:
    - Network interfaces and their status
    - Routing table entries
    - Active UDP connections (for QUIC detection)
    - Current firewall rules (if QUIC-only mode is active)
    
    Used for: Troubleshooting network connectivity and configuration issues
    """
    print("[diag] ip -br link:\n" + ns_sh(ns, "ip -br link").stdout, end="")
    print("[diag] ip -4 route:\n" + ns_sh(ns, "ip -4 route").stdout, end="")
    print("[diag] ss -u -n | head:\n" + ns_sh(ns, "ss -u -n | head -n 20").stdout, end="")
    print("[diag] nft quiconly:\n" + ns_sh(ns, "nft list ruleset | sed -n '/table inet quiconly/,$p'").stdout, end="")

# -------------------------- Web Navigation and Performance Measurement -----------------------
# Core functions for automated browser testing and performance data collection
# Core functions for automated browser testing and performance data collection

def measure_nav(ns: str, chrome_bin: str, url: str, headless: bool):
    """
    Perform a single web page navigation measurement using Selenium WebDriver
    
    This function:
    1. Starts Chrome browser with optimized settings for QUIC measurements
    2. Navigates to the target URL
    3. Waits for page load completion
    4. Extracts performance timing metrics
    5. Returns timing data
    
    Args:
        ns: Network namespace to run Chrome in
        chrome_bin: Path to Chrome binary
        url: Target website URL to measure
        headless: Whether to run Chrome in headless mode
        
    Returns:
        dict: Performance metrics including:
            - plt_ms: Page Load Time in milliseconds
            - t_wall_start: Wall clock start time
            - t_wall_end: Wall clock end time
    
    Key Chrome optimizations for measurements:
    - Disables caching to ensure fresh loads
    - Enables QUIC protocol explicitly
    - Reduces background noise (extensions, sync, etc.)
    - Uses incognito mode for clean state
    - Extended timeout for packet loss scenarios
    """
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    # Verify Chrome version compatibility with ChromeDriver
    major = get_chrome_major(ns, chrome_bin)
    if not major:
        raise SystemExit(f"Chrome not found/unreadable in {ns}: {chrome_bin}")
    cdrv = find_chromedriver_for_major(major)
    if not cdrv:
        raise SystemExit(f"chromedriver {major}.x not found. Install one aligned with Chrome {major}.x")

    # Create namespace wrapper for Chrome binary
    with ns_wrapper(chrome_bin, ns) as chrome_in_ns:
        opts = Options()
        
        # Essential Chrome flags for measurement accuracy
        for a in ("--no-first-run","--disable-extensions","--disable-background-networking",
                  "--disable-sync","--incognito","--disk-cache-size=1",
                  "--disable-application-cache","--disable-back-forward-cache",
                  "--disable-background-timer-throttling","--disable-renderer-backgrounding",
                  "--disable-features=TranslateUI,BlinkGenPropertyTrees",
                  # QUIC protocol enablement
                  "--enable-quic","--enable-features=UseDnsHttpsSvcb,UseDnsHttpsSvcbAlpn",
                  # Namespace compatibility
                  "--no-sandbox","--disable-dev-shm-usage","--remote-debugging-pipe"):
            opts.add_argument(a)
            
        # Configure headless mode if requested
        if headless:
            opts.add_argument("--headless=new")
            opts.add_argument("--hide-scrollbars") 
            opts.add_argument("--disable-gpu")
            
        # Create isolated Chrome profile for this measurement
        profile = tempfile.mkdtemp(prefix="chrome-prof-")
        opts.add_argument(f"--user-data-dir={profile}")
        opts.binary_location = chrome_in_ns
        
        # Initialize WebDriver with configured options
        drv = webdriver.Chrome(service=Service(executable_path=cdrv), options=opts)

        try:
            # Extended timeout for packet loss scenarios (was 45s, now 120s)
            drv.set_page_load_timeout(120)
            
            # Force disable caching through DevTools Protocol
            # This ensures we measure actual network performance, not cache hits
            drv.execute_cdp_cmd('Network.setCacheDisabled', {'cacheDisabled': True})
            drv.execute_cdp_cmd('Network.clearBrowserCache', {})
            
            # Record start time and navigate to target URL
            t0 = time.time()
            drv.get(url)
            
            # Wait for page to fully load (check every 100ms for up to 45 seconds)
            for _ in range(450):
                if drv.execute_script("return document.readyState") == "complete":
                    break
                time.sleep(0.1)
            
            # Extract navigation timing data from browser's Performance API
            nav = drv.execute_script("return performance.getEntriesByType('navigation')[0] || {}")
            
            # Calculate Page Load Time from navigation timing
            plt_ms = (nav.get("loadEventEnd", 0) - nav.get("startTime", 0)) or 0
            
            # Brief pause to ensure all network activity completes
            time.sleep(5)
            
            return {"plt_ms": plt_ms, "t_wall_start": t0, "t_wall_end": time.time()}
            
        except KeyboardInterrupt:
            print(f"[INFO] Navigation interrupted by user for {url}")
            return {"plt_ms": 0, "t_wall_start": t0, "t_wall_end": time.time()}
        except Exception as e:
            print(f"[ERROR] Navigation failed for {url}: {e}")
            return {"plt_ms": 0, "t_wall_start": t0, "t_wall_end": time.time()}
        finally:
            # Cleanup: close browser and remove temporary profile
            drv.quit()
            shutil.rmtree(profile, ignore_errors=True)

@contextmanager
def tcpdump_veth1(ns: str, outfile: Path, bpf: str):
    """
    Context manager for packet capture during navigation
    
    Args:
        ns: Network namespace to capture in
        outfile: Path for output pcap file
        bpf: Berkeley Packet Filter expression (e.g., "udp and port 443")
        
    This function:
    1. Starts tcpdump in background before navigation
    2. Yields control for navigation to occur
    3. Stops tcpdump gracefully after navigation
    
    Why packet capture is essential:
    - Records all network traffic for detailed analysis
    - Enables post-measurement verification of packet dropping
    - Provides data for inter-arrival time analysis
    - Documents actual QUIC protocol usage
    """
    # Start tcpdump process in the namespace
    # -i veth1: capture on virtual interface
    # -w: write to file
    # -U: packet-buffered output (immediate write)
    # -n: don't resolve hostnames (faster)
    proc = run_in_ns(ns, f"tcpdump -i veth1 -w {shlex.quote(str(outfile))} -U -n {shlex.quote(bpf)}")
    
    # Brief delay to ensure tcpdump is ready
    time.sleep(0.6)
    
    try:
        yield  # Allow navigation to proceed
    finally:
        # Stop tcpdump gracefully
        try: 
            os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        except Exception: 
            pass
        try: 
            proc.wait(timeout=5)
        except Exception: 
            pass

def capture_one(ns: str, url: str, tag: str, headless: bool, chrome_bin: str):
    """
    Perform one complete measurement: navigation + packet capture
    
    Args:
        ns: Network namespace
        url: Website URL to test
        tag: Unique identifier for this measurement
        headless: Chrome headless mode flag
        chrome_bin: Chrome binary path
        
    Returns:
        tuple: (pcap_path, navigation_metrics)
        
    This function combines:
    - Packet capture (tcpdump for UDP/QUIC traffic)
    - Web navigation (Selenium/Chrome)
    - Basic capture validation
    
    The packet capture filter "udp and port 443" specifically targets
    QUIC traffic, which is what we're analyzing for packet loss impact.
    """
    pcap = PCAPS_DIR / f"{tag}.pcap"
    nav = {}
    
    # Perform navigation with simultaneous packet capture
    with tcpdump_veth1(ns, pcap, "udp and port 443"):
        nav = measure_nav(ns, chrome_bin, url, headless)

    # Validate that we captured some packets
    try:
        # Use capinfos to count packets in capture file
        ci = ns_sh(ns, f"capinfos -c {shlex.quote(str(pcap))} 2>/dev/null | awk -F': ' '/Number of packets/ {{print $2}}'").stdout.strip()
        pkt = int(ci) if ci.isdigit() else (pcap.stat().st_size > 24)
    except Exception:
        # Fallback: check if file is larger than pcap header (24 bytes)
        pkt = (pcap.stat().st_size > 24)

    # Warn if no packets captured (site may not use QUIC)
    if not pkt:
        print(f"[warn] empty pcap for {url}. The site may not use QUIC.")
        
    return str(pcap), nav or {"plt_ms":0,"t_wall_start":0,"t_wall_end":0}

# -------------------------- Main Execution Logic ---------------------------------------
# Command-line interface and experiment orchestration
# Command-line interface and experiment orchestration

def main():
    """
    Main function that orchestrates the complete measurement experiment
    
    This function:
    1. Parses command-line arguments for experiment configuration
    2. Sets up the measurement environment (namespace, traffic control, etc.)
    3. Runs measurements according to the specified mode
    4. Saves results to CSV file with proper metadata
    
    Experiment modes:
    - 'off': Baseline measurements without packet dropping
    - 'fixed': Static drop rates at specified levels (e.g., 0%, 1%, 2%, 5%, 10%)
    - 'dynamic': Adaptive drop rates based on current traffic volume
    
    Output: CSV file with columns for mode, level, URL, repetition, and timing metrics
    """
    
    # Configure command-line argument parser
    parser = argparse.ArgumentParser(description="QUIC WF eval runner (Selenium + tcpdump + eBPF loader)")
    
    # Core experiment parameters
    parser.add_argument("--ns", default=NS_DEFAULT, 
                        help="Network namespace name for traffic isolation")
    parser.add_argument("--urls", default="urls.txt", 
                        help="File containing list of URLs to test")
    parser.add_argument("--mode", choices=["off","fixed","dynamic"], required=True,
                        help="Packet dropping mode: off=baseline, fixed=constant rate, dynamic=adaptive")
    
    # Fixed mode parameters
    parser.add_argument("--levels", default="0,1,2,5,10", 
                        help="Comma-separated drop percentages for fixed mode")
    parser.add_argument("--runs-per-level", type=int, default=10,
                        help="Number of measurement repetitions per drop level")
    
    # Dynamic mode parameters
    parser.add_argument("--dynamic-max-prob", type=int, default=50,
                        help="Maximum drop percentage in dynamic mode")
    parser.add_argument("--dynamic-min-pps", type=int, default=1000,
                        help="Minimum packets/sec for dynamic dropping activation")
    parser.add_argument("--dynamic-max-pps", type=int, default=100000,
                        help="Maximum packets/sec for full dynamic drop rate")
    
    # Browser and system configuration
    parser.add_argument("--headless", action=argparse.BooleanOptionalAction, default=True,
                        help="Run Chrome in headless mode (no GUI)")
    parser.add_argument("--quic-only", action=argparse.BooleanOptionalAction, default=True,
                        help="Install firewall rules to force QUIC protocol usage")
    parser.add_argument("--traffic-control", action=argparse.BooleanOptionalAction, default=True, 
                        help="Enable traffic control to isolate experiment traffic from host interference")
    
    args = parser.parse_args()

    # -------------------------- Environment Setup --------------------------
    
    # Create output directories for results and packet captures
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    PCAPS_DIR.mkdir(parents=True, exist_ok=True)

    # Verify namespace access permissions early (prevents cryptic errors later)
    test_ns = subprocess.run(["ip", "netns", "exec", args.ns, "true"], capture_output=True)
    if test_ns.returncode != 0:
        raise SystemExit(f"Permission denied to enter namespace '{args.ns}'. "
                         f"Run: sudo -E ./run_full_evaluation.sh (or start this script with sudo -E). "
                         f"Details: {test_ns.stderr.decode().strip()}")

    # Detect and verify Chrome browser installation
    chrome = pick_chrome_binary()
    
    # Install QUIC-only firewall rules if requested
    # This forces websites to use QUIC instead of falling back to TCP
    if args.quic_only:
        quic_only_install(args.ns)
        atexit.register(lambda: quic_only_uninstall(args.ns))  # Cleanup on exit

    # Clean any leftover processes from previous experiments
    clean_namespace(args.ns)
    
    # Setup traffic control for experiment isolation (default enabled)
    # This prevents host system traffic from interfering with measurements
    tc_interface = None
    if args.traffic_control:
        tc_interface = setup_traffic_control()
        if tc_interface:
            atexit.register(cleanup_traffic_control)  # Cleanup on exit
    
    # Auto-detect network interface for eBPF attachment
    ifname = autodetect_iface(args.ns)
    
    # Print preflight diagnostic information
    print(f"[preflight] ns={args.ns} if={ifname} chrome={chrome} major={get_chrome_major(args.ns, chrome)}")
    print("[preflight] ping 1.1.1.1 ->", ns_sh(args.ns, "ping -c1 -W1 1.1.1.1 >/dev/null && echo OK || echo FAIL").stdout.strip())

    # Load URL list from file (skip comments and empty lines)
    urls = [u.strip() for u in open(args.urls) if u.strip() and not u.startswith("#")]
    
    # Set random seed for reproducible URL ordering across runs
    random.seed(123)

    # -------------------------- Measurement Execution --------------------------
    
    # Initialize CSV file for results with comprehensive metadata
    file_exists = CSV_PATH.exists()
    with open(CSV_PATH, "a" if file_exists else "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["mode","level","url","rep","pcap","plt_ms","t_wall_start","t_wall_end",
                                          "dyn_max_prob","dyn_min_pps","dyn_max_pps"])
        if not file_exists:
            w.writeheader()

        # Execute measurements based on selected mode
        if args.mode == "off":
            """
            Baseline Mode: No packet dropping
            
            This establishes the reference performance without any network interference.
            Essential for calculating relative performance degradation in other modes.
            """
            print("[INFO] Starting baseline measurements (mode: off)")
            set_loader(args.ns, "off", ifname)  # Ensure eBPF loader is disabled
            
            for rep in range(1, args.runs_per_level+1):
                random.shuffle(urls)  # Randomize URL order to minimize ordering effects
                for url in tqdm(urls, desc=f"baseline {rep}/{args.runs_per_level}"):
                    # Create unique tag for this measurement
                    tag = f"off_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                    
                    # Perform measurement and save results
                    pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                    w.writerow({"mode":"off","level":0,"url":url,"rep":rep,"pcap":pcap,
                                "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":""}); f.flush()

        elif args.mode == "fixed":
            """
            Fixed Mode: Constant packet drop rates
            
            Tests specific drop percentages to understand the relationship between
            packet loss and web performance. Each level is tested multiple times
            for statistical significance.
            """
            levels = [int(x) for x in args.levels.split(",") if x.strip()]
            
            for lvl in levels:
                print(f"[INFO] Starting fixed mode measurements at level {lvl}%")
                
                # Configure eBPF loader for this drop rate
                set_loader(args.ns, "fixed", ifname, fixed_prob=lvl)
                
                for rep in range(1, args.runs_per_level+1):
                    random.shuffle(urls)  # Randomize URL order
                    for url in tqdm(urls, desc=f"fixed {lvl}% rep {rep}/{args.runs_per_level}"):
                        tag = f"lvl{lvl}_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                        
                        # Perform measurement and save results with drop level metadata
                        pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                        w.writerow({"mode":"fixed","level":lvl,"url":url,"rep":rep,"pcap":pcap,
                                    "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                    "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":""}); f.flush()
            
            # Disable eBPF loader after fixed mode measurements
            set_loader(args.ns, "off", ifname)

        else:  # dynamic mode
            """
            Dynamic Mode: Adaptive packet dropping
            
            Simulates realistic network conditions where packet loss varies based on
            current traffic load. Higher traffic rates trigger higher drop rates,
            mimicking network congestion scenarios.
            """
            # Configure eBPF loader for dynamic mode with specified parameters
            set_loader(args.ns, "dynamic", ifname,
                       dyn_max=args.dynamic_max_prob, 
                       dyn_min_pps=args.dynamic_min_pps, 
                       dyn_max_pps=args.dynamic_max_pps)
            
            for rep in range(1, args.runs_per_level+1):
                random.shuffle(urls)  # Randomize URL order
                for url in tqdm(urls, desc=f"dynamic rep {rep}/{args.runs_per_level}"):
                    tag = f"dyn_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                    
                    # Perform measurement and save results with dynamic mode metadata
                    pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                    w.writerow({"mode":"dynamic","level":-1,"url":url,"rep":rep,"pcap":pcap,
                                "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                "dyn_max_prob":args.dynamic_max_prob,"dyn_min_pps":args.dynamic_min_pps,"dyn_max_pps":args.dynamic_max_pps}); f.flush()
            
            # Disable eBPF loader after dynamic mode measurements
            set_loader(args.ns, "off", ifname)

if __name__ == "__main__":
    main()
