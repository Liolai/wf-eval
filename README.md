# eBPF-based Website Fingerprinting Defense for QUIC

This project evaluates an eBPF-based packet manipulation defense against website fingerprinting (WF) attacks on QUIC traffic. It measures both the effectiveness of traffic pattern obfuscation (privacy) and its impact on web performance (usability).

The core contribution of this final framework is the **Combined Asymmetric Defense**: it applies a fixed probability packet drop on the ingress channel (downlink) to organically mutate temporal bursts, while simultaneously injecting dynamic dummy packets on the egress channel (uplink) to mask client request patterns.

---

## ⚠️ Important Notice Regarding Data (Read First)

To maintain a clean and lightweight Git repository for handover, **all raw `.pcap` files (which amount to tens of gigabytes) have been intentionally removed** from the `out/pcaps/` directory. 

However, all necessary extracted features and metadata required for plotting and clustering analysis have been successfully preserved in the pre-computed **`out/nav_metrics.csv`** (8.1 MB). 
👉 **You can directly run the plotting scripts to reproduce the thesis figures without needing to re-run the massive network captures.** If you wish to collect new raw PCAP data, simply re-run the measurement pipeline.

---

## 📁 Repository Structure

### Core Execution Scripts
- **`run_batch_measurements.py`** - The core measurement engine using Selenium WebDriver, supporting Round-Robin batching and all defense modes (off, drop, dummy, combined).
- **`setup_netns.sh`** / **`clean_netns.sh`** - Network namespace setup/cleanup for pristine traffic isolation and Traffic Control (TC) rate limiting.
- **`analyse_pcaps.py`** - Packet capture analysis that extracts IAT, packet sizes, and generates the CSV metrics.

### eBPF Components (`ebpf/`)
- **`packet_dropper.bpf.c`** - eBPF program for selective ingress packet dropping.
- **`dummy_generator.bpf.c`** - eBPF program for egress dummy packet injection via `bpf_clone_redirect`.
- **`loader.c`** - User-space orchestrator to attach/detach eBPF programs to the TC hooks.

### Plotting & Analysis
- **`plot_results.py`**, **`plot_tradeoff.py`**, **`plot_tsne.py`** - Scripts to generate the evaluation figures (Accuracy, PLT, Security-Usability Trade-off) from the CSV data.

---

## 🚀 Quick Start & Usage Instructions

### 1. Environment Setup
Create a Python virtual environment and install the required dependencies:

python3 -m venv venv
source venv/bin/activate
pip install scapy pandas matplotlib seaborn scikit-learn selenium tqdm

Compile the eBPF programs (requires clang, llvm, libbpf-dev):


cd ebpf
make clean && make
cd ..
2. Generating Plots from Preserved Data (No capture required)
To reproduce the figures presented in the thesis using the provided out/nav_metrics.csv data, simply run:

Bash
# Generate main bar charts and the Trade-off scatter plot
python3 plot_results.py
python3 plot_tradeoff.py

# Generate t-SNE dimensionality reduction visualization
python3 plot_tsne.py
(All generated plots will be saved inside the out/ or out/plots_thesis/ directory).

3. Running New Measurements (From Scratch)
If you need to collect new traffic traces, you must set up the namespace and run the batch measurement script.

Step A: Setup Isolated Network

Bash
./setup_netns.sh
Step B: Execute Measurements
You can use the python script directly to control specific defense modes. Note: sudo is typically required to attach eBPF programs and manipulate network namespaces.

Bash
# Example 1: Run the Baseline (No defense)
sudo python3 run_batch_measurements.py --mode off

# Example 2: Run the Combined Asymmetric defense 
# (Fixes drop at 5%, scales dummy injection at 5, 10, 15, 20%)
sudo python3 run_batch_measurements.py --mode combined --combined-drop-prob 5 --levels "5,10,15,20" --runs-per-level 100 --batch-size 20
Step C: Parse PCAPs & Cleanup

Bash
# Extract features from newly captured PCAPs into CSV
python3 analyse_pcaps.py

# Clean up namespace and background Chrome processes
./clean_netns.sh
🔬 System Architecture
Plaintext
┌─────────────────────────────────────────────┐
│            NETWORK NAMESPACE (wfns)         │
│  ┌─────────────┐  ┌──────────────────────┐  │
│  │   Browser   │  │ eBPF TC Data Plane   │  │
│  │  + Selenium │  │ - Packet Dropper     │  │
│  │             │  │ - Dummy Generator    │  │
│  └─────────────┘  └──────────────────────┘  │
│         │                    │              │
│         ▼                    ▼              │
│  ┌─────────────────────────────────────────┐│
│  │      Network Interface (veth1 <-> veth0)││
│  └─────────────────────────────────────────┘│
└─────────────────┬───────────────────────────┘
                  │
           ┌──────▼──────┐
           │  INTERNET   │
           │ (Test Sites)│
           └─────────────┘
