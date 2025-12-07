import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os
import csv

# --- 修复 Matplotlib 权限警告 ---
os.environ['MPLCONFIGDIR'] = '/tmp'

# === 配置 ===
CSV_FILE = "out/nav_metrics.csv"
OUTPUT_DIR = "out/plots_new"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 设置风格
sns.set_theme(style="whitegrid")

# 定义最终的12列列名
COLUMN_NAMES = [
    "mode", "level", "url", "rep", "pcap", "plt_ms", 
    "t_wall_start", "t_wall_end", "dyn_max_prob", 
    "dyn_min_pps", "dyn_max_pps", "extra_param"
]

def robust_read_csv(filename):
    """
    强壮的读取函数：
    能够同时读取旧数据(11列)和新数据(12列)，
    自动给旧数据补上空列，防止报错。
    """
    data = []
    print(f"正在手动清洗并读取: {filename} ...")
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                # 跳过空行
                if not row: continue
                
                # 如果是表头行(包含 'mode' 字样)，跳过
                if row[0] == 'mode':
                    continue
                
                # === 关键修复逻辑 ===
                # 如果只有11列(旧数据)，补一个空字符串变成12列
                if len(row) == 11:
                    row.append('')
                
                # 只保留正好12列的数据，防止异常
                if len(row) == 12:
                    data.append(row)
                else:
                    # 如果还是不对，记录一下（通常不会发生）
                    pass
                    
        # 转换为 DataFrame
        df = pd.DataFrame(data, columns=COLUMN_NAMES)
        
        # 将数字列转换为数字类型 (因为手动读取全是字符串)
        df['plt_ms'] = pd.to_numeric(df['plt_ms'], errors='coerce')
        df['level'] = pd.to_numeric(df['level'], errors='coerce')
        
        return df
        
    except Exception as e:
        print(f"读取失败: {e}")
        return None

def get_label(row):
    """生成符合博士要求的标签"""
    mode = str(row['mode'])
    level = str(row['level'])
    extra = str(row['extra_param']) if pd.notna(row['extra_param']) else ''
    
    if mode == 'off':
        return "Baseline"
    elif mode == 'fixed':
        return f"Drop (Fixed {level}%)"
    elif mode == 'dummy_fixed' or mode == 'dummy':
        return f"Dummy (Fixed {level}%)"
    elif mode == 'dummy_dynamic':
        return "Dummy (Dynamic)"
    elif mode == 'dynamic':
        return "Drop (Dynamic)"
    elif mode == 'combined':
        drop_val = extra.replace('drop=', '') if 'drop=' in extra else '?'
        return f"Combined (Dr{drop_val}% + Du{level}%)"
    
    return f"{mode} {level}"

def main():
    if not os.path.exists(CSV_FILE):
        print(f"错误: 找不到文件 {CSV_FILE}")
        return

    # 使用强壮读取函数
    df = robust_read_csv(CSV_FILE)
    
    if df is None or df.empty:
        print("错误: 数据为空或读取失败")
        return

    print("数据读取成功！")
    print(f"总行数: {len(df)}")
    # 打印最后几行看看 Combined 模式
    print("最后3行预览:")
    print(df.tail(3)[['mode', 'level', 'extra_param']])

    # 1. 生成标签
    df['Label'] = df.apply(get_label, axis=1)

    # 2. 画 Performance Cost
    plt.figure(figsize=(12, 7))
    
    # 过滤无效数据
    plot_df = df.dropna(subset=['plt_ms'])
    
    if plot_df.empty:
        print("没有有效的 PLT 数据可画图")
        return

    # 排序
    order = plot_df.groupby('Label')['plt_ms'].mean().sort_values().index
    
    # 画图
    sns.barplot(data=plot_df, x='Label', y='plt_ms', order=order, palette="viridis", capsize=.1)
    
    plt.title("Performance Cost Analysis (Total Defense)")
    plt.ylabel("Page Load Time (ms)")
    plt.xlabel("Strategy")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    save_path = f"{OUTPUT_DIR}/cost_analysis.png"
    plt.savefig(save_path)
    print(f"\n✅ 图表已成功生成: {save_path}")
    print("请在文件浏览器中打开查看！")

if __name__ == "__main__":
    main()
