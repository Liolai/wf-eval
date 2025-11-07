// ebpf/dummy_generator.bpf.c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
// 我们不再包含 "parse_helpers.h"
// 而是直接包含原始头文件
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h> // 用于 IPPROTO_UDP

#define QUIC_PORT 443

/* struct state 和 map 定义 (与 loader.c 兼容) */
struct state {
    __u64 packet_count;     // 用作: egress_cloned_count
    __u64 dropped_count;    // (不再使用，但为兼容保留)
    __u32 drop_probability; // 用作: clone_probability
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct state);
} state_map SEC(".maps");


/*
 * =========================================
 * EGRESS (出站) 程序 (唯一的程序)
 * =========================================
 *
 * *** BPF 验证器修复 ***
 * 我们必须在函数内部进行内联解析，并且 *不* 使用 ip->ihl,
 * 因为验证器无法跟踪可变偏移量。
 * 我们假设 IP 头部固定为 20 字节。
 */
SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 key = 0;
    struct state *s;

    // --- 1. 内联解析 (验证器友好) ---
    
    // L2 (Ethernet)
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK; // 只处理 IPv4

    // L3 (IP) - 假设 20 字节头部, *不* 使用 ihl
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + 20 > data_end) // <-- 假设 20 字节 (常量)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // L4 (UDP)
    struct udphdr *udp = (void *)ip + 20; // <-- 假设 20 字节 (常量)
    if ((void *)udp + sizeof(*udp) > data_end)
        return TC_ACT_OK;

    // 检查端口
    if (udp->dest != bpf_htons(QUIC_PORT) && udp->source != bpf_htons(QUIC_PORT))
        return TC_ACT_OK;

    // L5 (Payload)
    void *payload = (void *)udp + sizeof(*udp);
    if (payload > data_end)
        return TC_ACT_OK;
        
    // --- 解析完毕 ---

    s = bpf_map_lookup_elem(&state_map, &key);
    if (!s) {
        return TC_ACT_OK; 
    }

    // 3. 检查克隆概率
    if ((bpf_get_prandom_u32() % 100) < s->drop_probability) {
        
        // 4. 发送原始包:
        // 克隆当前的 skb (它是原始包), 并将其发送到 Egress。
        bpf_clone_redirect(skb, skb->ifindex, 0); 
        
        // 5. 更新计数器
        __sync_fetch_and_add(&s->packet_count, 1);

        // 6. 创建虚拟包 (修改 skb)
        unsigned int cleartext_len = 9; // (同样的简化)

        // 验证器知道 'payload' 是有效的
        if (payload + cleartext_len > data_end) {
            return TC_ACT_OK; // 包太短
        }

        void *payload_to_corrupt = payload + cleartext_len;
        
        // 7. 循环写入随机字节
        #pragma unroll
        for (int i = 0; i < 100; i++) {
            int offset = i * sizeof(__u32);

            // 验证器检查: 确保写入在边界内
            if (payload_to_corrupt + offset + sizeof(__u32) > data_end) {
                break; 
            }

            __u32 random_bytes = bpf_get_prandom_u32();
            
            // *** 修复 ***
            // 偏移量现在是从 'data' (skb->data) 开始计算的。
            // 验证器可以静态地证明这个偏移量是有效的，
            // 因为我们所有的计算都基于 *常量* (sizeof, 20)。
            long skb_off = (char *)payload_to_corrupt - (char *)data + offset;

            bpf_skb_store_bytes(skb, 
                                skb_off, // 使用这个干净的、可验证的偏移量
                                &random_bytes, 
                                sizeof(random_bytes), 
                                BPF_F_RECOMPUTE_CSUM);
        }
    }
    
    // 8. 发送虚拟包 (如果被修改了) 或 原始包 (如果未修改)
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
