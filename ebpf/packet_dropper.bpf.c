// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

/* This struct holds the shared state between kernel and user space. */
struct state {
    __u64 packet_count;       // A counter for all packets seen.
    __u64 dropped_count;      // A counter for dropped packets.
    __u32 drop_probability;   // The current drop probability (0-100), set by user space.
};

/* The eBPF map definition. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct state);
} state_map SEC(".maps");

// We pass a simple integer (1 for ingress, 2 for egress) to avoid string relocation issues.
static __always_inline int handle_packet(struct __sk_buff *skb, __u32 direction)
{
    __u32 key = 0;
    struct state *s;

    s = bpf_map_lookup_elem(&state_map, &key);
    if (!s) {
        return TC_ACT_OK;
    }

    __sync_fetch_and_add(&s->packet_count, 1);

    if ((bpf_get_prandom_u32() % 100) < s->drop_probability) {
        __sync_fetch_and_add(&s->dropped_count, 1);
        // Use %u to print the direction integer instead of %s.
        bpf_printk("TC dir=%u: Dropping packet, probability=%u\n", direction, s->drop_probability);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    // Pass '1' to represent Ingress
    return handle_packet(skb, 1);
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    // Pass '2' to represent Egress
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
