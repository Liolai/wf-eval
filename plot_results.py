#!/usr/bin/env python3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

OUT = Path("out")
PLOTS = OUT / "plots"  # Use out/plot directory
PLOTS.mkdir(parents=True, exist_ok=True)

# --- 1. 加载数据 ---
try:
    summary = pd.read_csv(OUT / "summary.csv")
    iat_up = pd.read_csv(OUT / "iat_up.csv")
    iat_down = pd.read_csv(OUT / "iat_down.csv")
except FileNotFoundError as e:
    print(f"Error: {e}.")
    print("Please run analyse_pcaps.py first.")
    exit(1)

# --- 2. 关键修复：创建一个“组合标签”列 ---
def create_label(df):
    if 'mode' not in df.columns:
        print("Error: 'mode' column not found in CSV. Did analyse_pcaps.py run correctly?")
        return df # 返回原始df以避免崩溃

    # 填充 'off' 模式可能缺失的 'mode'
    df['mode'] = df['mode'].fillna('off')
    
    # 将 level 转换为字符串
    label = df['level'].astype(str)
    
    # 定义条件
    is_off = (df['mode'] == 'off')
    is_dynamic = (df['mode'] == 'dynamic')
    is_fixed = (df['mode'] == 'fixed')
    is_dummy = (df['mode'] == 'dummy') # <-- (这里是修正点)

    # 应用新标签
    label[is_off] = "0% (Baseline)"
    label[is_dynamic] = "Dynamic"
    label[is_fixed] = label[is_fixed].str.replace(r'\.0$', '', regex=True) + "% (Fixed)"
    label[is_dummy] = label[is_dummy].str.replace(r'\.0$', '', regex=True) + "% (Dummy)"
    
    df['label'] = label
    return df

summary = create_label(summary)
iat_up = create_label(iat_up)
iat_down = create_label(iat_down)

# Debug: 打印新的标签信息
print(f"Summary data shape: {summary.shape}")
print(f"Labels found: {sorted(summary['label'].unique())}")
print(f"Label counts: {summary['label'].value_counts().sort_index()}")
print(f"Metrics available: {list(summary.columns)}")
print()

def format_value_with_unit(value, unit):
    """Format values with appropriate unit conversion for readability"""
    if unit == "bytes":
        if value >= 1024*1024:
            return f"{value/(1024*1024):.1f}", "MB"
        elif value >= 1024:
            return f"{value/1024:.1f}", "KB" 
        else:
            return f"{value:.0f}", "bytes"
    elif unit == "ms" and value >= 1000:
        return f"{value/1000:.2f}", "seconds"
    else:
        return f"{value:.1f}", unit

def agg_bar_ci(df, metric, fname, title, ylabel=None, unit=""):
    """Create bar chart with confidence intervals and professional styling"""
    
    # --- 修复 3: 按新的 'label' 列分组 ---
    g = df.groupby("label")[metric].agg(['mean','count','std']).reset_index()
    g['sem'] = g['std'] / np.sqrt(g['count'])
    g['ci95'] = 1.96 * g['sem']
    
    # --- 修复 4: 动态创建排序顺序 ---
    all_labels = sorted(df['label'].unique())
    level_order = ['0% (Baseline)']
    # 智能排序：1%, 1% (dummy), 10%, 10% (dummy), 2%, 2% (dummy)...
    other_labels = sorted([l for l in all_labels if l not in level_order and l != 'Dynamic'], 
                          key=lambda x: (int(x.split('%')[0]), x))
    level_order.extend(other_labels)
    if "Dynamic" in all_labels:
        level_order.append("Dynamic")

    g['label'] = pd.Categorical(g['label'], categories=level_order, ordered=True)
    g = g.sort_values('label').dropna(subset=['label']) # 丢弃任何意外的标签

    plt.figure(figsize=(12, 7)) # 增加宽度以容纳更多条
    bars = plt.bar(g['label'].astype(str), g['mean'], yerr=g['ci95'], capsize=4, 
                   color='steelblue', alpha=0.7, edgecolor='navy', linewidth=0.8)
    
    # --- 修复 5: 更新X轴标签 ---
    plt.xlabel("Experiment Mode and Level", fontsize=12, fontweight='bold')
    plt.xticks(rotation=45, ha='right') # 旋转标签以防重叠
    
    # (Y轴标签逻辑保持不变)
    y_label = ylabel if ylabel else metric
    if unit:
        if unit == "bytes":
            max_val = g['mean'].max()
            if max_val >= 1024*1024:
                y_label += " (MB)"
                g['mean'] = g['mean'] / (1024*1024)
                g['ci95'] = g['ci95'] / (1024*1024)
            elif max_val >= 1024:
                y_label += " (KB)"  
                g['mean'] = g['mean'] / 1024
                g['ci95'] = g['ci95'] / 1024
            else:
                y_label += " (bytes)"
        else:
            y_label += f" ({unit})"
    
    plt.ylabel(y_label, fontsize=12, fontweight='bold')
    plt.title(title, fontsize=14, fontweight='bold', pad=20)
    
    # (在条形图上显示值的逻辑保持不变)
    for i, (idx, row) in enumerate(g.iterrows()):
        formatted_val, display_unit = format_value_with_unit(row['mean'], unit)
        plt.text(i, row['mean'] + row['ci95'] + max(g['mean']) * 0.02, 
                 f"{formatted_val}\n(n={int(row['count'])})", 
                 ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # (样式逻辑保持不变)
    plt.grid(True, axis='y', alpha=0.3, linestyle='--')
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(PLOTS / fname, dpi=180, bbox_inches='tight')
    plt.close()
    
    # --- 修复 6: 更新调试打印信息 ---
    print(f"✓ Generated {fname}: {len(g)} labels found: {list(g['label'])}")

def plot_comparative_cdf(df, metric_col, fname, title, xlabel):
    """Create comparative CDF plot showing all levels on the same chart"""
    if len(df) == 0:
        print(f"⚠️  Warning: Empty data for {fname}")
        return

    plt.figure(figsize=(10, 7))

    # --- 修复 7: 按 'label' 分组和上色 ---
    all_labels = sorted(df['label'].unique())
    colors = plt.cm.viridis(np.linspace(0, 1, len(all_labels)))
    label_colors = dict(zip(all_labels, colors))

    # Plot CDF for each label
    for label, label_data in df.groupby('label'): # <-- 按 'label' 分组
        if len(label_data) == 0:
            continue

        series = label_data[metric_col].dropna()
        if len(series) == 0:
            continue

        x = np.sort(series.values)
        x = x * 1000  # FIX 1: Convert to milliseconds (原脚本中已有)
        y = np.arange(1, len(x)+1) / len(x)

        # --- 修复 8: 更新图例标签 ---
        label_text = f"{label} (n={len(series)})" # e.g., "10% (Dummy) (n=12345)"
        
        plt.plot(x, y, linewidth=2.5, alpha=0.8, color=label_colors[label],
                 label=label_text) # <-- 使用新的 label_text

    plt.xlabel("Inter-Arrival Time (ms)", fontsize=12, fontweight='bold') # FIX 2: Update Label (原脚本中已有)
    plt.ylabel("Cumulative Distribution Function (CDF)", fontsize=12, fontweight='bold')
    plt.title(title, fontsize=14, fontweight='bold', pad=20)

    # (样式逻辑保持不变)
    plt.grid(True, which='both', axis='both', alpha=0.3, linestyle='--')
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)

    plt.xlim(0, 100) # FIX 3: Zoom in on X-axis (原脚本中已有)
    plt.xscale('symlog')
    plt.legend(loc='lower right', frameon=True, fancybox=True, shadow=True)

    plt.savefig(PLOTS / fname, dpi=180, bbox_inches='tight') # FIX 4: (原脚本中已有)
    plt.close()

    # --- 修复 9: 更新调试打印信息 ---
    print(f"✓ Generated comparative {fname}: {len(df['label'].unique())} labels compared")

# (主运行逻辑不需要修改，因为它只是调用上面的函数)
# Generate professional bar charts with clear labels and units
plot_configs = [
    ("plt_ms", "bar_plt_ms.png", "Page Load Time vs Packet Loss", "Page Load Time", "ms"),
    ("bytes_up", "bar_bytes_up.png", "Uplink Traffic vs Packet Loss", "Bytes Transmitted (Uplink)", "bytes"),
    ("bytes_down", "bar_bytes_down.png", "Downlink Traffic vs Packet Loss", "Bytes Received (Downlink)", "bytes"), 
    ("pkt_up", "bar_pkt_up.png", "Uplink Packet Count vs Packet Loss", "Packets Transmitted (Uplink)", "packets"),
    ("pkt_down", "bar_pkt_down.png", "Downlink Packet Count vs Packet Loss", "Packets Received (Downlink)", "packets"),
    ("duration_s", "bar_duration.png", "Connection Duration vs Packet Loss", "Flow Duration", "seconds"),
]

print("Generating bar charts with professional styling...")
for metric, filename, title, ylabel, unit in plot_configs:
    if metric in summary.columns:
        agg_bar_ci(summary, metric, filename, title, ylabel, unit)
    else:
        print(f"⚠️  Warning: Metric '{metric}' not found in data")

# Generate Comparative Inter-Arrival Time CDFs
print("\nGenerating Comparative Inter-Arrival Time CDFs...")

# IAT data already has level information - no need to merge
plot_comparative_cdf(iat_up, "iat_s", "cdf_iat_uplink_comparative.png",
                     "Comparative Inter-Arrival Time Distribution - Upload Traffic",
                     "Inter-Arrival Time (ms)")

plot_comparative_cdf(iat_down, "iat_s", "cdf_iat_downlink_comparative.png", 
                     "Comparative Inter-Arrival Time Distribution - Download Traffic",
                     "Inter-Arrival Time (ms)")

print("\nAll plots generated successfully in out/plots/")
