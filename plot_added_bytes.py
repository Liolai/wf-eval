import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os

OUTPUT_DIR = "out/plots_thesis"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 博士要求: different probabilities of dummy packets
# 填入你观察到或计算出的额外流量开销比例 (%)
data = {
    'Dummy Rate (%)': [0, 5, 10, 20],
    'Traffic Overhead (%)': [0, 5.2, 10.5, 21.0] # 替换为你的真实测量值
}
df_bytes = pd.DataFrame(data)

sns.set_theme(style="whitegrid", context="paper", font_scale=1.6)
plt.figure(figsize=(8, 6))

ax = sns.barplot(
    data=df_bytes,
    x='Dummy Rate (%)',
    y='Traffic Overhead (%)',
    color="#4c72b0", 
    edgecolor=".2",
    linewidth=1.5
)

plt.xlabel('Dummy Traffic Injection Rate (%)', labelpad=12, fontweight='bold')
plt.ylabel('Network Traffic Overhead (%)', labelpad=12, fontweight='bold')

for container in ax.containers:
    ax.bar_label(container, fmt='%.1f%%', padding=5, fontsize=13, fontweight='bold')

sns.despine(left=True)
plt.tight_layout()
save_path = os.path.join(OUTPUT_DIR, "added_bytes_cost.png")
plt.savefig(save_path, dpi=300)
print(f"✅ 流量开销图已生成: {save_path}")
