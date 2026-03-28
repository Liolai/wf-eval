import os
import glob
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.manifold import TSNE
from scapy.all import rdpcap, IP, UDP
from tqdm import tqdm

# ================= Configuration =================
PCAP_DIR = "out/pcaps"
OUTPUT_DIR = "out/plots_thesis" # 统一输出到这个文件夹
MAX_PACKETS = 100
SAMPLES_PER_SITE = 10 
TARGET_SITES = ["google", "facebook", "youtube", "nytimes", "wikipedia", "bbc", "amazon", "cnn"]
CLIENT_IP = "10.200.0.2"

# 【核心升级】和上面一样的字典，用来分类你的文件
CONFIGURATIONS = {
    "Baseline": "off_",
    "Drop_5": "ingress_lvl5", "Drop_10": "ingress_lvl10", "Drop_20": "ingress_lvl20",
    "Dummy_5": "dummy_lvl5", "Dummy_10": "dummy_lvl10", "Dummy_20": "dummy_lvl20",
    "Asym_10": "comb_dr5_du10", "Asym_15": "comb_dr5_du15", "Asym_20": "comb_dr5_du20",
    "Adaptive": "dummy_dynamic"
}
# ===============================================

os.makedirs(OUTPUT_DIR, exist_ok=True)

def extract_features(pcap_path):
    try:
        packets = rdpcap(pcap_path, count=MAX_PACKETS * 3)
    except Exception:
        return None
    sizes = []
    for pkt in packets:
        if IP in pkt and UDP in pkt:
            payload_len = len(pkt[UDP].payload)
            if payload_len == 0: continue
            if pkt[IP].src == CLIENT_IP:
                sizes.append(payload_len)
            else:
                sizes.append(-1 * payload_len)
            if len(sizes) >= MAX_PACKETS: break
    if len(sizes) < MAX_PACKETS:
        sizes += [0] * (MAX_PACKETS - len(sizes))
    return sizes

print(f"Scanning PCAPs in {PCAP_DIR}...")
pcap_files = glob.glob(os.path.join(PCAP_DIR, "*.pcap"))

# 提前提取所有可用文件的特征，存起来备用
extracted_data = []
print("Extracting features from all PCAPs...")
for p_path in tqdm(pcap_files):
    fname = os.path.basename(p_path)
    site = "Other"
    for s in TARGET_SITES:
        if s in fname.lower():
            site = s.capitalize()
            break
    if site == "Other": continue
    
    # 匹配 Mode
    assigned_mode = "Unknown"
    for mode_name, keyword in CONFIGURATIONS.items():
        if keyword in fname or keyword.replace("dummy_", "dummy_fixed_") in fname:
            assigned_mode = mode_name
            break
            
    if assigned_mode == "Unknown": continue
    
    feat = extract_features(p_path)
    if feat:
        extracted_data.append({'Data': feat, 'Site': site, 'Mode': assigned_mode})

if not extracted_data: exit("Error: No data found.")

full_df = pd.DataFrame(extracted_data)

# 封装画图函数
def process_and_plot_tsne(mode_name):
    mode_df = full_df[full_df['Mode'] == mode_name]
    if mode_df.empty:
        print(f"⚠️ Skipping {mode_name}: No data.")
        return
        
    def sample_group(group):
        if len(group) >= SAMPLES_PER_SITE:
            return group.sample(SAMPLES_PER_SITE, random_state=42)
        return group
        
    balanced_df = mode_df.groupby('Site', group_keys=False).apply(sample_group)
    
    if len(balanced_df) < 5:
        print(f"⚠️ Skipping {mode_name}: Not enough samples after balancing.")
        return

    print(f"🎨 Plotting {mode_name} ({len(balanced_df)} samples)...")
    X = np.array(balanced_df['Data'].tolist())
    perp = min(30, len(X) - 1)
    tsne = TSNE(n_components=2, random_state=42, init='pca', learning_rate='auto', perplexity=perp)
    X_embedded = tsne.fit_transform(X)
    balanced_df['x'] = X_embedded[:, 0]
    balanced_df['y'] = X_embedded[:, 1]

    sns.set_theme(style="white", context="talk", font_scale=1.2)
    plt.figure(figsize=(11, 7))
    sns.scatterplot(
        data=balanced_df, x='x', y='y', hue='Site', style='Site', 
        s=130, alpha=0.85, palette="deep"
    )
    plt.xlabel("Dimension 1", fontweight='bold', labelpad=10)
    plt.ylabel("Dimension 2", fontweight='bold', labelpad=10)
    plt.legend(title='Website', loc='center left', bbox_to_anchor=(1.02, 0.5), frameon=True, fontsize='medium', borderaxespad=0.)
    sns.despine()
    plt.tight_layout()
    
    out_path = os.path.join(OUTPUT_DIR, f"tsne_{mode_name}.png")
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()

# 批量生成所有图
print("\n=========================================")
for mode in CONFIGURATIONS.keys():
    process_and_plot_tsne(mode)
print("✅ 所有 t-SNE 聚类图已生成至 out/plots_thesis/！")
