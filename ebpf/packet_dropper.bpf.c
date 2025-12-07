// ebpf/packet_dropper.bpf.c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h" // 使用统一的 struct state

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct state);
} state_map SEC(".maps");

static __always_inline int handle_packet(struct __sk_buff *skb, __u32 direction)
{
    __u32 key = 0;
    struct state *s;

    s = bpf_map_lookup_elem(&state_map, &key);
    if (!s) return TC_ACT_OK;

    // 统计流量
    __sync_fetch_and_add(&s->packet_count, 1);
    
    // 应用丢包概率 (只看 drop_probability)
    if (s->drop_probability > 0) {
        if ((bpf_get_prandom_u32() % 100) < s->drop_probability) {
            __sync_fetch_and_add(&s->dropped_count, 1);
            return TC_ACT_SHOT; // 丢弃
        }
    }

    return TC_ACT_OK; // 放行
}

SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    return handle_packet(skb, 1);
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    // 修复：现在允许 Egress 丢包
    return handle_packet(skb, 2); 
}

char LICENSE[] SEC("license") = "GPL";
