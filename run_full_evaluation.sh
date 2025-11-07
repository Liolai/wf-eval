#!/usr/bin/env bash
set -euo pipefail

# ========================================================================
# Complete evaluation script for wf-eval project
# Runs everything from eBPF compilation to final plots
# ========================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Requires root privileges for ip netns exec / eBPF / tcpdump
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo -e "${YELLOW}[WARNING] Not running as root: restarting with sudo -E...${NC}"
    exec sudo -E env PATH="$PATH" "$0" "$@"
fi

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we are in the correct directory
if [[ ! -f "plot_results.py" || ! -d "ebpf" ]]; then
    print_error "Run this script from the wf-eval root directory"
    exit 1
fi

print_status "Starting complete wf-eval evaluation"
print_warning "COMPREHENSIVE EVALUATION MODE: This will run all three experiment types"
print_warning "Estimated completion time: 45-90 minutes depending on URLs and system performance"
print_warning "Experiments include: baseline (no drops), fixed drop levels (0-20%), and dynamic dropping"
START_TIME=$(date +%s)

# ========================================================================
# PHASE 0: Clean previous evaluation results
# ========================================================================
print_status "PHASE 0: Cleaning previous evaluation results"

if [[ -d "out" ]]; then
    print_warning "Existing 'out' directory found. Removing..."
    rm -rf out/
    print_success "Previous results removed"
else
    print_status "No previous results found"
fi

# Clean any remaining active eBPF processes
print_status "Checking for active eBPF processes..."
if pgrep -f "ebpf/loader" >/dev/null 2>&1; then
    print_warning "Terminating remaining active eBPF processes..."
    sudo pkill -f "ebpf/loader" || true
fi

# Clean existing namespace
print_status "Checking for existing namespaces..."
if ip netns list | grep -q "wfns"; then
    print_warning "Existing wfns namespace found. Removing..."
    sudo ip netns del wfns 2>/dev/null || true
    print_success "Previous namespace removed"
fi

# Clean remaining veth interfaces
print_status "Cleaning network interfaces..."
for veth in veth0 veth1; do
    if ip link show "$veth" >/dev/null 2>&1; then
        print_warning "Removing remaining $veth interface..."
        sudo ip link del "$veth" 2>/dev/null || true
    fi
done

# Clean any remaining Chrome/Chromium processes in namespace
print_status "Checking for remaining browser processes..."
if pgrep -f "chrome.*wfns\|chromium.*wfns" >/dev/null 2>&1; then
    print_warning "Terminating remaining browser processes..."
    sudo pkill -f "chrome.*wfns\|chromium.*wfns" || true
fi

# Clean system temporary files
print_status "Cleaning temporary files..."
sudo rm -f /tmp/chrome-profile-* /tmp/.org.chromium.* 2>/dev/null || true

print_success "Cleanup completed - environment ready for new evaluation"

# ========================================================================
# PHASE 1: Dependencies installation (if needed)
# ========================================================================
print_status "PHASE 1: Checking dependencies"

if command -v python3 >/dev/null 2>&1; then
    print_success "Python3 found"
else
    print_error "Python3 not found. Run first: ./install_dependencies.sh"
    exit 1
fi

# Check if Python dependencies are installed
if python3 -c "import pandas, numpy, matplotlib, scapy, selenium, tqdm" 2>/dev/null; then
    print_success "Python dependencies available"
elif [[ -f "venv/bin/activate" ]]; then
    print_status "Using project virtual environment..."
    source venv/bin/activate
    if python3 -c "import pandas, numpy, matplotlib, scapy, selenium, tqdm" 2>/dev/null; then
        print_success "Python dependencies available in venv"
    else
        print_error "Python dependencies missing in venv. Run: ./install_dependencies.sh"
        exit 1
    fi
else
    print_error "Python dependencies missing. Run first: ./install_dependencies.sh"
    exit 1
fi

# Check if system tools are available
for tool in clang gcc make ip iptables; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        print_error "$tool not found. Run first: ./install_dependencies.sh"
        exit 1
    fi
done

print_success "All dependencies are available"

# ========================================================================
# PHASE 2: eBPF compilation
# ========================================================================
print_status "PHASE 2: Compiling eBPF programs"

cd ebpf
print_status "Cleaning previous builds..."
make clean >/dev/null 2>&1 || true

print_status "Compiling packet_dropper.bpf.o and loader..."
if make; then
    print_success "eBPF compilation completed"
else
    print_error "Error during eBPF compilation"
    exit 1
fi

# Verify that files were created
if [[ ! -f "packet_dropper.bpf.o" || ! -f "loader" ]]; then
    print_error "eBPF files not found after compilation"
    exit 1
fi

cd ..

# ========================================================================
# PHASE 3: Network namespace setup
# ========================================================================
print_status "PHASE 3: Network namespace setup"

print_status "Configuring wfns namespace..."
if sudo ./setup_netns.sh; then
    print_success "Namespace configured correctly"
else
    print_error "Error during namespace configuration"
    exit 1
fi

# Verify that namespace was created
if ! ip netns list | grep -q "wfns"; then
    print_error "wfns namespace not found"
    exit 1
fi

# Basic connectivity test
print_status "Testing connectivity in namespace..."
if sudo ip netns exec wfns ping -c 1 1.1.1.1 >/dev/null 2>&1; then
    print_success "Connectivity verified"
else
    print_warning "Connectivity test failed, but proceeding anyway"
fi

# ========================================================================
# PHASE 4: Running measurements
# ========================================================================
print_status "PHASE 4: Running complete evaluation experiments"

# Create output directory
mkdir -p out/pcaps

print_status "Starting comprehensive measurement experiments (this will take considerable time)..."
print_warning "Running all three experiment modes: baseline, fixed drop levels, and dynamic dropping"

# Preserve important environment variables for Chrome/Selenium
export DISPLAY="${DISPLAY:-:0}"
export HOME="${HOME}"
export USER="${USER}"
export PATH="${PATH}"

# Use venv if available, otherwise run in current environment
if [[ -f "venv/bin/activate" ]] && [[ "$VIRTUAL_ENV" != *"venv"* ]]; then
    print_status "Running measurements in project virtual environment..."
    source venv/bin/activate
    USING_VENV=true
else
    USING_VENV=false
fi

# Test Chrome accessibility before starting measurements
print_status "Testing Chrome accessibility in namespace..."
if ! sudo ip netns exec wfns /usr/bin/google-chrome --version >/dev/null 2>&1; then
    print_warning "Chrome test failed, but proceeding anyway"
fi

# Test basic Python import
print_status "Testing Python selenium import..."
if ! python3 -c "from selenium import webdriver; print('Selenium import OK')" 2>/dev/null; then
    print_error "Selenium import failed"
    exit 1
fi

# Experiment 1: Baseline measurements (no eBPF, truly off)
print_status "Experiment 1/4: Baseline measurements (no packet dropping)"
if env DISPLAY="$DISPLAY" HOME="$HOME" USER="$USER" PATH="$PATH" python3 run_measurements.py --mode off --runs-per-level 10; then
    print_success "Baseline measurements completed"
else
    print_error "Error during baseline measurements"
    exit 1
fi

# Experiment 2: Fixed drop level measurements (skip 0% since we have baseline)
print_status "Experiment 2/4: Fixed drop level measurements (1%, 2%, 5%, 10%, 20%)"
if env DISPLAY="$DISPLAY" HOME="$HOME" USER="$USER" PATH="$PATH" python3 run_measurements.py --mode fixed --levels "1,2,5,10,20" --runs-per-level 10; then
    print_success "Fixed drop level measurements completed"
else
    print_error "Error during fixed drop level measurements"
    exit 1
fi

# --- 这是你新添加的块 ---
# Experiment 3: Dummy packet generation measurements
print_status "Experiment 3/4: Dummy packet generation measurements (1%, 2%, 5%, 10%, 20%)"
if env DISPLAY="$DISPLAY" HOME="$HOME" USER="$USER" PATH="$PATH" python3 run_measurements.py \
    --mode dummy \
    --levels "1,2,5,10,20" \
    --runs-per-level 10; then
    print_success "Dummy packet generation measurements completed"
else
    print_error "Error during dummy packet generation measurements"
    exit 1
fi
# --- 新添加的块结束 ---

# Experiment 3: Dynamic packet dropping measurements
print_status "Experiment 4/4: Dynamic packet dropping measurements"
if env DISPLAY="$DISPLAY" HOME="$HOME" USER="$USER" PATH="$PATH" python3 run_measurements.py --mode dynamic --runs-per-level 10 --dynamic-max-prob 50 --dynamic-min-pps 1000 --dynamic-max-pps 100000; then
    print_success "Dynamic measurements completed"
else
    print_error "Error during dynamic measurements"
    exit 1
fi

print_success "All measurement experiments completed successfully"

# Verify that output files were created
if [[ ! -f "out/nav_metrics.csv" ]]; then
    print_error "nav_metrics.csv file not found"
    exit 1
fi

# Show some basic statistics
NAV_ROWS=$(wc -l < out/nav_metrics.csv)
print_success "Collected $((NAV_ROWS - 1)) navigation samples"

# ========================================================================
# PHASE 5: PCAP analysis
# ========================================================================
print_status "PHASE 5: PCAP file analysis"

print_status "Processing captured packets..."
if python3 analyse_pcaps.py; then
    print_success "PCAP analysis completed"
else
    print_error "Error during PCAP analysis"
    exit 1
fi

# Verify that analysis files were created
for file in "out/summary.csv" "out/iat_up.csv" "out/iat_down.csv"; do
    if [[ ! -f "$file" ]]; then
        print_error "File $file not found"
        exit 1
    fi
done

print_success "Analysis files generated correctly"

# ========================================================================
# PHASE 6: Plot generation
# ========================================================================
print_status "PHASE 6: Generating plots and visualizations"

print_status "Creating statistical plots..."
if python3 plot_results.py; then
    print_success "Plots generated correctly"
else
    print_error "Error during plot generation"
    exit 1
fi

# Verify that plots directory was created
if [[ ! -d "out/plots" ]]; then
    print_error "out/plots directory not found"
    exit 1
fi

# Count generated plots
PLOT_COUNT=$(find out/plots -name "*.png" | wc -l)
print_success "Generated $PLOT_COUNT plots in out/plots/"

# ========================================================================
# PHASE 7: Cleanup and final report
# ========================================================================
print_status "PHASE 7: Finalization"

# Calculate total execution time
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION_MIN=$((DURATION / 60))
DURATION_SEC=$((DURATION % 60))

print_success "======================================================"
print_success "     COMPREHENSIVE EVALUATION COMPLETED SUCCESSFULLY!"
print_success "======================================================"
echo
print_success "All three experiment modes completed:"
print_success "  ✓ Baseline measurements (no packet dropping)"
print_success "  ✓ Fixed drop level measurements (0%, 1%, 2%, 5%, 10%, 20%)"  
print_success "  ✓ Dynamic packet dropping measurements"
echo
print_status "Total execution time: ${DURATION_MIN}m ${DURATION_SEC}s"
echo
print_status "Generated files:"
echo "  • out/nav_metrics.csv     - Raw navigation metrics"
echo "  • out/summary.csv         - Aggregated statistics"
echo "  • out/iat_up.csv         - Uplink inter-arrival times"
echo "  • out/iat_down.csv       - Downlink inter-arrival times"
echo "  • out/plots/*.png        - Plots and visualizations ($PLOT_COUNT files)"
echo "  • out/pcaps/*.pcap       - Packet capture files"
echo
print_status "To view results:"
echo "  • Open plots in out/plots/"
echo "  • Examine CSV files for detailed analysis"
echo "  • PCAP files are available for further analysis"
echo

# Optional: show a quick summary of measurements
if command -v python3 >/dev/null 2>&1 && [[ -f "out/nav_metrics.csv" ]]; then
    print_status "Quick results summary:"
    python3 -c "
import pandas as pd
try:
    df = pd.read_csv('out/nav_metrics.csv')
    print(f'  • Total experiments conducted: {len(df)} measurements')
    print(f'  • Experiment modes: {sorted(df[\"mode\"].unique())}')
    if 'level' in df.columns:
        print(f'  • Drop levels tested: {sorted(df[\"level\"].unique())}')
        print(f'  • Samples per level: {dict(df[\"level\"].value_counts().sort_index())}')
    print(f'  • Average Page Load Time: {df[\"plt_ms\"].mean():.1f}ms (±{df[\"plt_ms\"].std():.1f})')
    print(f'  • URLs tested: {df[\"url\"].nunique()} unique websites')
    mode_counts = df[\"mode\"].value_counts()
    for mode, count in mode_counts.items():
        print(f'  • {mode.title()} mode: {count} measurements')
except Exception as e:
    print(f'  • Error calculating summary: {e}')
"
elif command -v python3 >/dev/null 2>&1 && [[ -f "out/summary.csv" ]]; then
    print_status "Quick results summary (from aggregated data):"
    python3 -c "
import pandas as pd
try:
    df = pd.read_csv('out/summary.csv')
    print(f'  • Drop levels tested: {sorted(df[\"level\"].unique())}')
    print(f'  • Samples per level: {dict(df[\"level\"].value_counts().sort_index())}')
    print(f'  • Average Page Load Time: {df[\"plt_ms\"].mean():.1f}ms (±{df[\"plt_ms\"].std():.1f})')
    print(f'  • Total bytes up/down: {df[\"bytes_up\"].sum()}/{df[\"bytes_down\"].sum()}')
except Exception as e:
    print(f'  • Error calculating summary: {e}')
"
fi

print_success "wf-eval evaluation completed!"

# Optional: automatic namespace cleanup (uncomment if desired)
# print_status "Cleaning up namespace..."
# sudo ip netns del wfns 2>/dev/null || true
# print_success "Cleanup completed"
