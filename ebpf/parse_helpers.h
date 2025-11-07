// ebpf/parse_helpers.h
#ifndef __PARSE_HELPERS_H
#define __PARSE_HELPERS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h> // <-- 修复: 添加这个头文件

#define QUIC_PORT 443

// 定义一个结构体来保存解析结果
struct packet_headers {
    struct ethhdr *eth;
    struct iphdr  *ip;
    struct udphdr *udp;
    void *payload;
};

/* * 辅助函数：解析 L2/L3/L4 头部
 * @return: 1 表示成功解析到 UDP 负载, 0 表示非 UDP 或包错误
 */
static __always_inline int parse_udp_headers(struct __sk_buff *skb, struct packet_headers *headers)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    // 1. L2 (Ethernet)
    headers->eth = data;
    if ((void *)headers->eth + sizeof(*headers->eth) > data_end)
        return 0;

    if (headers->eth->h_proto != bpf_htons(ETH_P_IP))
        return 0; // 只处理 IPv4

    // 2. L3 (IP)
    headers->ip = (struct iphdr *)(headers->eth + 1);
    if ((void *)headers->ip + sizeof(*headers->ip) > data_end)
        return 0;

    if (headers->ip->protocol != IPPROTO_UDP) // <-- 现在 IPPROTO_UDP 已被定义
        return 0; // 只处理 UDP

    // 3. L4 (UDP)
    headers->udp = (struct udphdr *)((void *)headers->ip + (headers->ip->ihl * 4));
    if ((void *)headers->udp + sizeof(*headers->udp) > data_end)
        return 0;
    
    // 4. Payload
    headers->payload = (void *)(headers->udp + 1);
    if (headers->payload > data_end)
        return 0;
    
    return 1; // 解析成功
}

#endif // __PARSE_HELPERS_H// ebpf/parse_helpers.h
#ifndef __PARSE_HELPERS_H
#define __PARSE_HELPERS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h> // <-- 修复: 添加这个头文件

#define QUIC_PORT 443

// 定义一个结构体来保存解析结果
struct packet_headers {
    struct ethhdr *eth;
    struct iphdr  *ip;
    struct udphdr *udp;
    void *payload;
};

/* * 辅助函数：解析 L2/L3/L4 头部
 * @return: 1 表示成功解析到 UDP 负载, 0 表示非 UDP 或包错误
 */
static __always_inline int parse_udp_headers(struct __sk_buff *skb, struct packet_headers *headers)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    // 1. L2 (Ethernet)
    headers->eth = data;
    if ((void *)headers->eth + sizeof(*headers->eth) > data_end)
        return 0;

    if (headers->eth->h_proto != bpf_htons(ETH_P_IP))
        return 0; // 只处理 IPv4

    // 2. L3 (IP)
    headers->ip = (struct iphdr *)(headers->eth + 1);
    if ((void *)headers->ip + sizeof(*headers->ip) > data_end)
        return 0;

    if (headers->ip->protocol != IPPROTO_UDP) // <-- 现在 IPPROTO_UDP 已被定义
        return 0; // 只处理 UDP

    // 3. L4 (UDP)
    headers->udp = (struct udphdr *)((void *)headers->ip + (headers->ip->ihl * 4));
    if ((void *)headers->udp + sizeof(*headers->udp) > data_end)
        return 0;
    
    // 4. Payload
    headers->payload = (void *)(headers->udp + 1);
    if (headers->payload > data_end)
        return 0;
    
    return 1; // 解析成功
}

#endif // __PARSE_HELPERS_H
