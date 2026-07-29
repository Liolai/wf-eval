// ebpf/dummy_generator.bpf.c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h" // 现在我们使用 parse_helpers.h 里的 struct state

/* * Map 定义
 * 注意：struct state 现在来自 parse_helpers.h，包含了 dummy_probability
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct state);
} state_map SEC(".maps");


SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 key = 0;
    struct state *s;

    // --- 1. 获取状态 ---
    s = bpf_map_lookup_elem(&state_map, &key);
    if (!s) return TC_ACT_OK;

    // --- 2. 简单的包过滤 (确保是 UDP/QUIC) ---
    // 这里使用简化版内联解析，避免引用 parse_helpers.h 可能带来的复杂依赖问题，
    // 或者你可以直接用 parse_udp_headers 如果它通过了验证器。
    // 这里保留你原本的内联写法以确保稳定性：

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + 20 > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + 20;
    if ((void *)udp + sizeof(*udp) > data_end) return TC_ACT_OK;

    if (udp->dest != bpf_htons(QUIC_PORT) && udp->source != bpf_htons(QUIC_PORT))
        return TC_ACT_OK;

    // Packet managed by us
    __sync_fetch_and_add(&s->packet_count, 1);
    __sync_fetch_and_add(&s->egress_count, 1);

    void *payload = (void *)udp + sizeof(*udp);
    if (payload > data_end) return TC_ACT_OK;

    // --- 3. Combined Logic (混合策略逻辑) ---

    // 步骤 A: 丢包 (Drop)
    // 如果设置了 drop_probability (比如 Combined 模式)，先尝试丢包
    if (s->drop_probability > 0) {
        if ((bpf_get_prandom_u32() % 100) < s->drop_probability) {
             __sync_fetch_and_add(&s->dropped_count, 1);
             return TC_ACT_SHOT; // 直接丢弃，不发假包
        }
    }

    // 步骤 B: 假包 (Dummy/Clone)
    // 如果包没被丢弃，检查 dummy_probability 来决定是否生成假包
    if ((bpf_get_prandom_u32() % 100) < s->dummy_probability) {

        // 1. 克隆并发送原始包
        bpf_clone_redirect(skb, skb->ifindex, 0);

        __sync_fetch_and_add(&s->cloned_count, 1); // 统计假包数量

        // 2. 修改当前的包 (skb) 使其成为"假包" (Payload Corruption)
        unsigned int cleartext_len = 9;
        if (payload + cleartext_len > data_end) return TC_ACT_OK;

        void *payload_to_corrupt = payload + cleartext_len;

        #pragma unroll
        for (int i = 0; i < 20; i++) { // 减少循环次数以防验证器超时，20次通常够混淆了
            int offset = i * sizeof(__u32);
            if (payload_to_corrupt + offset + sizeof(__u32) > data_end) break;

            __u32 random_bytes = bpf_get_prandom_u32();
            long skb_off = (char *)payload_to_corrupt - (char *)data + offset;

            bpf_skb_store_bytes(skb, skb_off, &random_bytes, sizeof(random_bytes), BPF_F_RECOMPUTE_CSUM);
        }
    }

    // 如果没被 Drop，也没变成 Dummy (或者变成了 Dummy)，最终都要放行
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
