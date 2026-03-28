import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os

# ================= Configuration =================
CSV_PATH = "out/nav_metrics.csv"
OUTPUT_DIR = "out/plots_clean"
# 输出文件名改为更通用的名字，因为标题已移除
OUTPUT_FILENAME = "cost_analysis_bar.png"
# =================================================

os.makedirs(OUTPUT_DIR, exist_ok=True)

print(f"Reading data from: {CSV_PATH} ...")
try:
    df = pd.read_csv(CSV_PATH, encoding='utf-8', encoding_errors='replace')
    df = df.dropna(axis=1, how='all')
except Exception as e:
    print(f"Error: {e}")
    exit()

# ------------------- 1. 数据过滤 -------------------
# 只保留 Baseline 和 Combined
df_clean = df[df['mode'].isin(['off', 'combined'])].copy()
# 只保留 Dummy 10, 20, 30 的数据
df_clean = df_clean[df_clean['level'] <= 30]

# ------------------- 2. 标签清洗 (符合博士要求) -------------------
def create_label(row):
    mode = row['mode']
    if mode == 'off':
        # Baseline 的 Dummy Rate 是 0
        return "0"
    elif mode == 'combined':
        # Combined 模式直接返回纯数字，例如 "10"
        return str(int(row['level']))
    return "Other"

df_clean['Label_Num'] = df_clean.apply(create_label, axis=1)

# ------------------- 3. 统计计算 -------------------
plot_df = df_clean.groupby('Label_Num')['plt_ms'].agg(['mean', 'sem']).reset_index()
plot_df.rename(columns={'mean': 'plt_ms', 'sem': 'error'}, inplace=True)

# 排序：确保按数字顺序排列 (0, 10, 20, 30)
plot_df['sort_key'] = plot_df['Label_Num'].astype(int)
plot_df = plot_df.sort_values('sort_key')
order = plot_df['Label_Num'].tolist()


sns.set_theme(style="ticks", context="talk", font_scale=1.1)
plt.figure(figsize=(8, 6))


unified_color = "#4c72b0" # Seaborn deep blue

ax = sns.barplot(
    data=plot_df,
    x='Label_Num',
    y='plt_ms',
    order=order,
    color=unified_color, # 统一颜色
    capsize=.1,
    edgecolor=".3", # 边框颜色加深一点
    linewidth=1.5,
    errorbar=None
)

# 添加误差线
plt.errorbar(
    x=range(len(plot_df)),
    y=plot_df['plt_ms'],
    yerr=plot_df['error'],
    fmt='none',
    c='black',
    capsize=5,
    elinewidth=1.5
)


plt.ylabel('Page Load Time (ms)', labelpad=10, fontweight='bold')

# 【修改点】X轴：明确单位是百分比 (%)
plt.xlabel('Dummy Traffic Rate (%)', labelpad=10, fontweight='bold')

# X轴刻度标签：保持水平，字体清晰
plt.xticks(rotation=0)

# 数值标注 (放在柱子内部或上方)
for i, v in enumerate(plot_df['plt_ms']):
    # 根据数值高度决定放里面还是外面
    offset = -150 if v > 500 else 50
    color = 'white' if v > 500 else 'black'
    ax.text(i, v + offset, f"{v:.0f}", color=color, ha='center', va='center', fontweight='bold', fontsize=12)

# 调整 Y 轴范围
plt.ylim(0, plot_df['plt_ms'].max() * 1.1)

# 去掉顶部和右侧边框
sns.despine()
plt.tight_layout()

output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)
plt.savefig(output_path, dpi=300, bbox_inches='tight')

print(f"\n✅ 柱状图已生成: {output_path}")
print("特点: 无标题, 统一颜色, X轴纯数字, 坐标轴带单位(%)和(ms)。")
