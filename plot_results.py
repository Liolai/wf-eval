#!/usr/bin/env python3
"""
plot_results.py (Final Polished Version)

Features:
1. FILTERS: Only shows Baseline, 5%, and 20% for Dummy/Fixed (Cleaner).
2. ZOOMED TRADEOFF: Cuts off the extreme outliers to focus on the relevant area (0-100% Cost).
3. DEBUGGING: Prints what data is actually found to diagnose missing Ingress bars.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from scipy.stats import ks_2samp

# --- 1. Setup ---
OUT = Path("out")
PLOTS = OUT / "plots"
PLOTS.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    'font.size': 14,
    'axes.titlesize': 16,
    'axes.labelsize': 14,
    'legend.fontsize': 12,
    'figure.titlesize': 18,
    'font.family': 'serif',
    'figure.figsize': (8, 6),
    'lines.linewidth': 2.5
})

# --- 2. Load Data ---
print("Loading CSV data...")
try:
    summary = pd.read_csv(OUT / "summary.csv")
    iat_up = pd.read_csv(OUT / "iat_up.csv")
    iat_down = pd.read_csv(OUT / "iat_down.csv")
    
    # Debugging: Print found modes to verify Ingress data existence
    print(f"DEBUG: Modes found in summary.csv: {summary['mode'].unique()}")
    if 'ingress' in summary['mode'].unique():
        print(f"DEBUG: Ingress levels found: {summary[summary['mode']=='ingress']['level'].unique()}")
    else:
        print("WARNING: No 'ingress' data found in CSV!")

except FileNotFoundError:
    print("Error: CSV files not found. Run analyse_pcaps.py first.")
    exit(1)

# --- 3. Data Cleaning & Filtering ---
def clean_labels_and_filter(df):
    """
    1. Creates clean labels.
    2. FILTERS out levels 1, 2, 10 for Dummy/Fixed (keeps 0, 5, 20).
    """
    if 'mode' not in df.columns: return df
    
    # Ensure types
    df['mode'] = df['mode'].fillna('off').astype(str)
    df['level'] = df['level'].fillna(0).astype(int)
    
    # FILTER: Keep only Baseline (0), 5%, 20%, or Dynamic
    # We allow Ingress to keep all its levels for now to see what we have
    keep_levels = [0, 5, 20]
    
    # Create a mask for filtering
    # Logic: Keep if (mode is dynamic) OR (mode is ingress) OR (level is in [0, 5, 20])
    mask = (df['mode'] == 'dynamic') | (df['mode'] == 'ingress') | (df['level'].isin(keep_levels))
    df = df[mask].copy()
    
    labels = []
    sort_keys = []
    
    for _, row in df.iterrows():
        m = row['mode']
        l = row['level']
        
        if m == 'off':
            labels.append("Baseline")
            sort_keys.append(0)
        elif m == 'dynamic':
            labels.append("Dynamic")
            sort_keys.append(999)
        elif m == 'fixed':
            labels.append(f"{l}% Fixed")
            sort_keys.append(l)
        elif m == 'dummy':
            labels.append(f"{l}% Dummy")
            sort_keys.append(l + 1000)
        elif m == 'ingress':
            labels.append(f"{l}% Ingress")
            sort_keys.append(l + 2000)
        else:
            labels.append(f"{m} {l}")
            sort_keys.append(9999)
            
    df['label'] = labels
    df['sort_key'] = sort_keys
    return df.sort_values('sort_key')

summary = clean_labels_and_filter(summary)
iat_up = clean_labels_and_filter(iat_up)
iat_down = clean_labels_and_filter(iat_down)

# --- 4. Plotting Functions ---

def get_98th_percentile(df, labels):
    all_values = []
    for label in labels:
        vals = df[df['label'] == label]['iat_s'].dropna().values
        all_values.extend(vals)
    if not all_values: return 1.0
    return np.percentile(all_values, 98) * 1000

def plot_performance_bar(df, mode_filter, filename, title):
    """Generates bar charts."""
    if mode_filter == 'dummy':
        subset = df[(df['mode'] == 'off') | (df['mode'] == 'dummy')]
    elif mode_filter == 'fixed':
        subset = df[(df['mode'] == 'off') | (df['mode'] == 'fixed')]
    elif mode_filter == 'ingress':
        subset = df[(df['mode'] == 'off') | (df['mode'] == 'ingress')]
    else:
        subset = df
        
    if subset.empty or len(subset['label'].unique()) < 2:
        print(f"Skipping {filename}: Not enough data (Found: {subset['label'].unique()})")
        return

    g = subset.groupby("label").agg(
        plt_mean=('plt_ms', 'mean'),
        plt_sem=('plt_ms', 'sem'),
        sort_key=('sort_key', 'first')
    ).sort_values('sort_key').reset_index()
    
    g['ci95'] = 1.96 * g['plt_sem']
    
    plt.figure(figsize=(7, 6))
    bars = plt.bar(g['label'], g['plt_mean'], yerr=g['ci95'], capsize=5, 
                   color='royalblue', edgecolor='black', alpha=0.8)
    
    # Highlight Baseline in Gray
    for i, label in enumerate(g['label']):
        if "Baseline" in label:
            bars[i].set_color('gray')

    plt.title(title)
    plt.ylabel("Page Load Time (ms)")
    plt.xlabel("")
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(PLOTS / filename, dpi=300)
    plt.close()
    print(f"Generated {filename}")

def plot_cdf(df, mode_filter, filename, title):
    """Generates Zoomed CDFs."""
    if mode_filter == 'dummy':
        target_modes = ['off', 'dummy']
    elif mode_filter == 'fixed':
        target_modes = ['off', 'fixed']
    elif mode_filter == 'ingress':
        target_modes = ['off', 'ingress']
    
    subset = df[df['mode'].isin(target_modes)].copy()
    subset = subset.sort_values('sort_key')
    
    if subset.empty or len(subset['label'].unique()) < 2: 
        return

    plt.figure(figsize=(8, 6))
    unique_labels = subset['label'].unique()
    x_limit = get_98th_percentile(subset, unique_labels)
    
    colors = plt.cm.viridis(np.linspace(0, 0.9, len(unique_labels)))
    
    for i, label in enumerate(unique_labels):
        series = subset[subset['label'] == label]['iat_s'].dropna()
        if series.empty: continue
        
        sorted_data = np.sort(series.values) * 1000
        yvals = np.arange(1, len(sorted_data) + 1) / len(sorted_data)
        
        style = '--' if "Baseline" in label else '-'
        color = 'black' if "Baseline" in label else colors[i]
        width = 2 if "Baseline" in label else 3
        
        plt.plot(sorted_data, yvals, label=label, linestyle=style, color=color, linewidth=width)

    plt.title(title)
    plt.xlabel("Inter-Arrival Time (ms)")
    plt.ylabel("CDF")
    plt.xscale('symlog', linthresh=0.1)
    plt.xlim(0, x_limit) 
    plt.grid(True, linestyle='--', alpha=0.4)
    plt.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig(PLOTS / filename, dpi=300)
    plt.close()
    print(f"Generated {filename}")

def plot_tradeoff_zoomed(summary_df, iat_df):
    """Trade-off plot ZOOMED in (cutting out extreme outliers)."""
    results = []
    base_sum = summary_df[summary_df['mode'] == 'off']
    base_iat = iat_df[iat_df['mode'] == 'off']['iat_s'].dropna()
    
    if base_sum.empty or base_iat.empty: return
    base_plt = base_sum['plt_ms'].mean()
    
    for mode in ['fixed', 'dummy', 'ingress', 'dynamic']:
        # Note: We use the original summary_df here to calculate all points, 
        # but we will limit the axis view
        mode_data = summary_df[summary_df['mode'] == mode]
        levels = mode_data['level'].unique()
        
        for lvl in levels:
            curr_sum = mode_data[mode_data['level'] == lvl]
            if curr_sum.empty: continue
            
            # Cost: % Increase
            cost = ((curr_sum['plt_ms'].mean() - base_plt) / base_plt) * 100
            
            # Benefit: KS Distance
            curr_iat = iat_df[(iat_df['mode'] == mode) & (iat_df['level'] == lvl)]['iat_s'].dropna()
            if curr_iat.empty: continue
            benefit = ks_2samp(base_iat, curr_iat).statistic
            
            results.append({
                'label': f"{lvl}%",
                'mode': mode,
                'cost': cost,
                'benefit': benefit
            })
            
    res_df = pd.DataFrame(results)
    
    plt.figure(figsize=(9, 7))
    colors = {'fixed': 'red', 'dummy': 'green', 'ingress': 'orange', 'dynamic': 'purple'}
    markers = {'fixed': 'o', 'dummy': 's', 'ingress': '^', 'dynamic': 'D'}
    
    for mode in res_df['mode'].unique():
        subset = res_df[res_df['mode'] == mode]
        plt.scatter(subset['benefit'], subset['cost'], 
                    color=colors.get(mode, 'gray'),
                    marker=markers.get(mode, 'o'),
                    s=150, alpha=0.8, label=mode.capitalize())
        
        for _, row in subset.iterrows():
            plt.annotate(row['label'], (row['benefit'], row['cost']), 
                         xytext=(5, 5), textcoords='offset points', fontsize=11, fontweight='bold')

    plt.title("Trade-off: Performance Cost vs. Benefit (Zoomed)")
    plt.xlabel("Benefit (KS Distance)")
    plt.ylabel("Cost (% PLT Increase)")
    
    # --- ZOOM SETTINGS ---
    plt.xlim(-0.01, 0.25)   # X-axis limit
    plt.ylim(-5, 100)       # Y-axis limit (Cuts off the >100% outliers)
    # ---------------------
    
    plt.axhline(0, color='black', lw=0.8)
    plt.axvline(0, color='black', lw=0.8)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend(loc='upper left')
    plt.tight_layout()
    plt.savefig(PLOTS / "final_tradeoff_zoomed.png", dpi=300)
    plt.close()
    print("Generated final_tradeoff_zoomed.png")

# --- 5. Execution ---
print("--- Generating Final Plots ---")

# Performance Bars (Filtered 0, 5, 20)
plot_performance_bar(summary, 'dummy', "bar_perf_dummy.png", "Performance Cost: Dummy Strategy")
plot_performance_bar(summary, 'fixed', "bar_perf_fixed.png", "Performance Cost: Fixed Drop Strategy")
plot_performance_bar(summary, 'ingress', "bar_perf_ingress.png", "Performance Cost: Ingress Drop Strategy")

# CDFs (Filtered 0, 5, 20 + Zoomed)
plot_cdf(iat_up, 'dummy', "cdf_iat_dummy.png", "Traffic Obfuscation: Dummy Strategy")
plot_cdf(iat_up, 'fixed', "cdf_iat_fixed.png", "Traffic Obfuscation: Fixed Drop Strategy")
plot_cdf(iat_up, 'ingress', "cdf_iat_ingress.png", "Traffic Obfuscation: Ingress Drop Strategy")

# Trade-off (Zoomed)
plot_tradeoff_zoomed(summary, iat_up)

print("\nDone! Check out/plots/ folder.")
