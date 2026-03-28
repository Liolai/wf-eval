#!/bin/bash
echo "Starting Interleaved Adaptive Measurements..."

# 循环 10 次，每次跑 10 个数据 (总共各 100 个)
for i in {1..10}
do
    echo ">>> Round $i/10: Running 10 Baseline (off) tests..."
    sudo python3 run_batch_measurements.py --mode off --runs-per-level 10 --batch-size 10

    echo ">>> Round $i/10: Running 10 Adaptive tests..."
    sudo python3 run_batch_measurements.py --mode dummy_dynamic --levels 20 --dynamic-max-prob 20 --dynamic-min-pps 500 --dynamic-max-pps 10000 --runs-per-level 10 --batch-size 10
done

echo "✅ All interleaved measurements finished!"
