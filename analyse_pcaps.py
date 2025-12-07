#!/usr/bin/env python3
import csv
from pathlib import Path
from scapy.all import PcapReader, UDP
import argparse 

parser = argparse.ArgumentParser(
    description="Analyze PCAP files and merge metrics based on nav_metrics.csv.",
    formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument(
    "input_dir",
    nargs="?", 
    default="out", 
    help="The input/output directory containing nav_metrics.csv (default: 'out')"
)
args = parser.parse_args()

BASE_DIR = Path(args.input_dir) 

NAV_CSV = BASE_DIR / "nav_metrics.csv"
SUMMARY_CSV = BASE_DIR / "summary.csv"
IAT_UP = BASE_DIR / "iat_up.csv"
IAT_DOWN = BASE_DIR / "iat_down.csv"

print(f"--- Analyzing data from: {BASE_DIR} ---")

def load_runs():
    try:
        with open(NAV_CSV) as f:
            return list(csv.DictReader(f))
    except FileNotFoundError:
        print(f"Error: {NAV_CSV} not found.")
        print("Please run run_measurements.py first.")
        exit(1)

def analyse_pcap(pcap_path: str):
    first_ts = last_ts = None
    bytes_up = bytes_down = 0
    pkt_up = pkt_down = 0
    last_ts_up = last_ts_down = None
    iats_up, iats_down = [], []

    try:
        with PcapReader(pcap_path) as pcap:
            for pkt in pcap:
                if not pkt.haslayer(UDP):
                    continue
                udp = pkt[UDP]
                ts = float(pkt.time)
                sport, dport = int(udp.sport), int(udp.dport)

                if dport == 443:  # client -> server
                    pkt_up += 1; bytes_up += len(bytes(pkt))
                    if last_ts_up is not None: iats_up.append(ts - last_ts_up)
                    last_ts_up = ts
                elif sport == 443:  # server -> client
                    pkt_down += 1; bytes_down += len(bytes(pkt))
                    if last_ts_down is not None: iats_down.append(ts - last_ts_down)
                    last_ts_down = ts
                else:
                    continue

                if first_ts is None: first_ts = ts
                last_ts = ts
    except (FileNotFoundError, IsADirectoryError) as e: 
        print(f"Warning: Failed to process pcap {pcap_path}: {e}")
    except Exception as e:
        print(f"Warning: Failed to process pcap {pcap_path} (other error): {e}")

    duration = (last_ts - first_ts) if (first_ts and last_ts) else 0.0
    return {
        "bytes_up": bytes_up, "bytes_down": bytes_down,
        "pkt_up": pkt_up, "pkt_down": pkt_down,
        "duration_s": duration, "iats_up": iats_up, "iats_down": iats_down
    }

def main():
    runs = load_runs()
    SUMMARY_CSV.parent.mkdir(parents=True, exist_ok=True)
    
    with open(SUMMARY_CSV, "w", newline="") as fs, \
         open(IAT_UP, "w", newline="") as fu, \
         open(IAT_DOWN, "w", newline="") as fd:
        
        summary_fields = [
            "mode", "url", "level", "rep", "pcap", "plt_ms", 
            "bytes_up", "bytes_down", "pkt_up", "pkt_down", "duration_s"
        ]
        
        if runs:
            all_fields = list(runs[0].keys())
            for f in reversed(summary_fields):
                if f in all_fields:
                    all_fields.remove(f)
                    all_fields.insert(0, f)
            pcap_metrics = ["bytes_up", "bytes_down", "pkt_up", "pkt_down", "duration_s"]
            final_fields = [f for f in all_fields if f not in pcap_metrics] + pcap_metrics
        else:
            final_fields = summary_fields

        ws = csv.DictWriter(fs, fieldnames=final_fields, extrasaction='ignore')
        ws.writeheader()

        iat_fields = ["mode", "url", "level", "rep", "iat_s"]
        wi_u = csv.DictWriter(fu, fieldnames=iat_fields); wi_u.writeheader()
        wi_d = csv.DictWriter(fd, fieldnames=iat_fields); wi_d.writeheader()

        print(f"Analyzing {len(runs)} measurement runs...")
        for row in runs:
            if "mode" not in row:
                # 这是一个旧的/损坏的 nav_metrics.csv，它没有 'mode' 列
                # 我们将手动为其添加 'mode'
                if row['level'] == '-1':
                    row['mode'] = 'dynamic'
                elif row['level'] == '0':
                    row['mode'] = 'off'
                else:
                    # 假设所有其他级别都是 'fixed'
                    row['mode'] = 'fixed' 
                print(f"Warning: 'mode' column missing. Guessed mode='{row['mode']}' from level='{row['level']}'.")


            # --- ( *** 这是关键的修复 *** ) ---
            # 我们不再“修复”路径。
            # 我们直接使用 CSV 中提供的原始路径。
            pcap_to_analyze = row["pcap"]
            # --- ( *** 修复结束 *** ) ---

            res = analyse_pcap(pcap_to_analyze)
            
            new_row = row.copy()
            new_row.update(res)
            
            ws.writerow(new_row)
            
            for x in res["iats_up"]:
                wi_u.writerow({"mode": row["mode"], "url": row["url"], "level": int(row["level"]), "rep": int(row["rep"]), "iat_s": x})
            for x in res["iats_down"]:
                wi_d.writerow({"mode": row["mode"], "url": row["url"], "level": int(row["level"]), "rep": int(row["rep"]), "iat_s": x})
        
        print(f"Analysis complete. Results saved to:")
        print(f" - {SUMMARY_CSV}")
        print(f" - {IAT_UP}")
        print(f" - {IAT_DOWN}")

if __name__ == "__main__":
    main()
