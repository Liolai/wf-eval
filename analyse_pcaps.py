#!/usr/bin/env python3
import csv
from pathlib import Path
from scapy.all import PcapReader, UDP

NAV_CSV = Path("out/nav_metrics.csv")
SUMMARY_CSV = Path("out/summary.csv")
IAT_UP = Path("out/iat_up.csv")
IAT_DOWN = Path("out/iat_down.csv")

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
    except Exception as e:
        print(f"Warning: Failed to process pcap {pcap_path}: {e}")
        # 返回空数据，但允许脚本继续

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
        
        # --- 修复 1: 在所有 fieldnames 中添加 "mode" ---
        
        summary_fields = [
            "mode", "url", "level", "rep", "pcap", "plt_ms", 
            "bytes_up", "bytes_down", "pkt_up", "pkt_down", "duration_s"
        ]
        ws = csv.DictWriter(fs, fieldnames=summary_fields)
        ws.writeheader()

        iat_fields = ["mode", "url", "level", "rep", "iat_s"]
        wi_u = csv.DictWriter(fu, fieldnames=iat_fields); wi_u.writeheader()
        wi_d = csv.DictWriter(fd, fieldnames=iat_fields); wi_d.writeheader()

        print(f"Analyzing {len(runs)} measurement runs...")
        for row in runs:
            # 检查 'mode' 列是否存在于输入的
            if "mode" not in row:
                print(f"Error: 'mode' column missing from input row in {NAV_CSV}. Aborting.")
                return

            res = analyse_pcap(row["pcap"])
            
            # --- 修复 2: 在写入 summary 时包含 "mode" ---
            ws.writerow({
                "mode": row["mode"], # <-- 关键修复
                "url": row["url"], "level": int(row["level"]), "rep": int(row["rep"]),
                "pcap": row["pcap"], "plt_ms": float(row["plt_ms"]),
                "bytes_up": res["bytes_up"], "bytes_down": res["bytes_down"],
                "pkt_up": res["pkt_up"], "pkt_down": res["pkt_down"],
                "duration_s": res["duration_s"]
            })
            
            # --- 修复 3: 在写入 IAT 数据时包含 "mode" ---
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
