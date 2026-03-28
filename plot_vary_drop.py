import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os

# ================= 配置区域 =================
# 确保这里的文件名和你 out 文件夹里的新 CSV 名字一致！
CSV_PATH = "out/nav_metrics_vary_drop.csv" 
OUTPUT_DIR = "out/plots_clean"
OUTPUT_FILENAME = "cost_analysis_drop_rate.png"
# ===========================================

os.makedirs(OUTPUT_DIR, exist_ok=True)

print(f"Reading data from: {CSV_PATH} ...")
try:
    df = pd.read_csv(CSV_PATH)
except FileNotFoundError:
    print(f"❌ 错误: 找不到文件 {CSV_PATH}")
    print("请检查 out 文件夹里的 csv 文件名，并修改脚本里的 CSV_PATH。")
    exit()

# ------------------- 1. 数据清洗 -------------------
# 这次我们只关心 combined 模式的数据
# 在 run_vary_drop.py 里，'level' 列存的就是 Drop Rate (5, 10, 15)
df_clean = df[df['mode'] == 'combined'].copy()

# ------------------- 2. 统计计算 -------------------
plot_df = df_clean.groupby('level')['plt_ms'].agg(['mean', 'sem']).reset_index()
plot_df.rename(columns={'mean': 'plt_ms', 'sem': 'error'}, inplace=True)

# 确保按丢包率排序 (5, 10, 15)
plot_df = plot_df.sort_values('level')

print("绘图数据预览 (Drop Rate vs PLT):")
print(plot_df)

# ------------------- 3. 绘图 (学术风格) -------------------
sns.set_theme(style="ticks", context="talk", font_scale=1.1)
plt.figure(figsize=(8, 6))

# 使用一种不同的颜色（比如砖红色）来区分这是“丢包实验”
unified_color = "#c44e52" 

ax = sns.barplot(
    data=plot_df,
    x='level',
    y='plt_ms',
    color=unified_color,
    capsize=.1,
    edgecolor=".3",
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

# ------------------- 4. 坐标轴修饰 -------------------
# 【关键】X轴现在代表 Packet Drop Rate
plt.xlabel('Packet Drop Rate (%)', labelpad=10, fontweight='bold')
plt.ylabel('Page Load Time (ms)', labelpad=10, fontweight='bold')

# 去掉标题 (博士要求)
# plt.title(...) 

# 数值标注
for i, v in enumerate(plot_df['plt_ms']):
    offset = -150 if v > 500 else 50
    color = 'white' if v > 500 else 'black'
    ax.text(i, v + offset, f"{v:.0f}", color=color, ha='center', va='center', fontweight='bold', fontsize=12)

plt.ylim(0, plot_df['plt_ms'].max() * 1.15)
sns.despine()
plt.tight_layout()

output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)
plt.savefig(output_path, dpi=300, bbox_inches='tight')

print(f"\n✅ 新图表已生成: {output_path}")
print("这张图展示了：在固定 20% 假包的情况下，丢包率从 5% 升到 15% 对网速的影响。")
