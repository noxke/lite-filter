#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/semaphore.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/random.h>

#include "log_utils.h"
#include "netlink_msg.h"
#include "netlink_utils.h"
#include "module_utils.h"
#include "netfilter_hook.h"
#include "filter_rule_utils.h"
#include "filter_nat_utils.h"


void nat_format(FilterNatNodeV4 *nat, char *buf, int size) {
    char *nat_str;
    IpPackInfoV4 *info;
    struct timespec64 current_time;
    long long int expired_sec;
    if (nat == NULL || buf == NULL) {
        return;
    }
    if (nat->nat_type == FILTER_SNAT) {
        nat_str = "SNAT";
    }
    else if (nat->nat_type == FILTER_DNAT) {
        nat_str = "DNAT";
    }
    // 获取当前时间
    ktime_get_real_ts64(&current_time);
    expired_sec = nat->expire_time - current_time.tv_sec;
    info = &(nat->ip_info);
    memset(buf, 0, size);
    switch (nat->protocol) {
        case IPPROTO_TCP:
            snprintf(buf, size, "[TCP] %pI4:%hu->%pI4:%hu %s %pI4:%hu expired: %llds", &(info->saddr), ntohs(info->sport), &(info->daddr), ntohs(info->dport), nat_str, &(nat->nataddr), ntohs(nat->natport), expired_sec);
            break;
        case IPPROTO_UDP:
            snprintf(buf, size, "[UDP] %pI4:%hu->%pI4:%hu %s %pI4:%hu expired: %llds", &(info->saddr), ntohs(info->sport), &(info->daddr), ntohs(info->dport), nat_str, &(nat->nataddr), ntohs(nat->natport), expired_sec);
            break;
        default:
            break;
    }
}

int do_nat(FilterNatNodeV4 *nat, IpPackInfoV4 *info, struct sk_buff *skb) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    int sum_len;
    if (nat == NULL ||info == NULL || skb == NULL) {
        return -1;
    }
    ip_header = ip_hdr(skb);
    sum_len = ip_header->tot_len - ip_header->ihl *4;

    if (nat->nat_type == FILTER_SNAT) {
        switch (info->protocol) {
            case IPPROTO_UDP:
                udp_header = udp_hdr(skb);
                // 修改源地址
                ip_header->saddr = nat->nataddr;
                udp_header->source = nat->natport;
                // 计算校验和
                ip_header->check = 0;
                ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
                udp_header->check = 0;
                skb->csum = csum_partial((u8 *)udp_header, sum_len, 0);
                udp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, sum_len, IPPROTO_UDP, skb->csum);
                break;
            case IPPROTO_TCP:
                tcp_header = tcp_hdr(skb);
                // 修改源地址
                ip_header->saddr = nat->nataddr;
                tcp_header->source = nat->natport;
                // 计算校验和
                ip_header->check = 0;
                ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
                tcp_header->check = 0;
                skb->csum = csum_partial((u8 *)tcp_header, sum_len, 0);
                tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, sum_len, IPPROTO_UDP, skb->csum);
                break;
        }
    }
    else if (nat->nat_type == FILTER_DNAT) {
        switch (info->protocol) {
            case IPPROTO_UDP:
                udp_header = udp_hdr(skb);
                // 修改目的地址
                ip_header->daddr = nat->nataddr;
                udp_header->dest = nat->natport;
                // 计算校验和
                ip_header->check = 0;
                ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
                udp_header->check = 0;
                skb->csum = csum_partial((u8 *)udp_header, sum_len, 0);
                udp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, sum_len, IPPROTO_UDP, skb->csum);
                break;
            case IPPROTO_TCP:
                tcp_header = tcp_hdr(skb);
                // 修改源地址
                ip_header->daddr = nat->nataddr;
                tcp_header->dest = nat->natport;
                // 计算校验和
                ip_header->check = 0;
                ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
                tcp_header->check = 0;
                skb->csum = csum_partial((u8 *)tcp_header, sum_len, 0);
                tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, sum_len, IPPROTO_UDP, skb->csum);
                break;
        }
    }
    return 0;
}

int do_nat2(FilterNatNodeV4 *nat, IpPackInfoV4 *info, struct sk_buff *skb) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    int sum_len;
    if (nat == NULL ||info == NULL || skb == NULL) {
        return -1;
    }
    ip_header = ip_hdr(skb);
    sum_len = ip_header->tot_len - ip_header->ihl *4;

    if (nat->nat_type == FILTER_SNAT) {
        switch (info->protocol) {
            case IPPROTO_UDP:
                udp_header = udp_hdr(skb);
                // 修改目的地址
                ip_header->daddr = nat->ip_info.saddr;
                udp_header->dest = nat->ip_info.sport;
                // 计算校验和
                ip_header->check = 0;
                ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
                udp_header->check = 0;
                skb->csum = csum_partial((u8 *)udp_header, sum_len, 0);
                udp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, sum_len, IPPROTO_UDP, skb->csum);
                break;
            case IPPROTO_TCP:
                tcp_header = tcp_hdr(skb);
                // 修改目的地址
                ip_header->daddr = nat->ip_info.saddr;
                tcp_header->dest = nat->ip_info.sport;
                // 计算校验和
                ip_header->check = 0;
                ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
                tcp_header->check = 0;
                skb->csum = csum_partial((u8 *)tcp_header, sum_len, 0);
                tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, sum_len, IPPROTO_UDP, skb->csum);
                break;
        }
    }
    else if (nat->nat_type == FILTER_DNAT) {
        switch (info->protocol) {
            case IPPROTO_UDP:
                udp_header = udp_hdr(skb);
                // 修改源地址
                ip_header->saddr = nat->ip_info.daddr;
                udp_header->source = nat->ip_info.dport;
                // 计算校验和
                ip_header->check = 0;
                ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
                udp_header->check = 0;
                skb->csum = csum_partial((u8 *)udp_header, sum_len, 0);
                udp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, sum_len, IPPROTO_UDP, skb->csum);
                break;
            case IPPROTO_TCP:
                tcp_header = tcp_hdr(skb);
                // 修改源地址
                ip_header->saddr = nat->ip_info.daddr;
                tcp_header->source = nat->ip_info.dport;
                // 计算校验和
                ip_header->check = 0;
                ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
                tcp_header->check = 0;
                skb->csum = csum_partial((u8 *)tcp_header, sum_len, 0);
                tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, sum_len, IPPROTO_UDP, skb->csum);
                break;
        }
    }
    return 0;
}

FilterNatNodeV4 *filter_nat_match_v4(IpPackInfoV4 *info, struct sk_buff *skb) {
    char nat_str[DEFAULT_STR_SIZE];
    FilterNatNodeV4 *next;
    struct timespec64 current_time;
    u64 current_sec;
    if (info == NULL || skb == NULL) {
        return NULL;
    }

    // 获取当前时间
    ktime_get_real_ts64(&current_time);
    current_sec = current_time.tv_sec;
    next = nf_hook_nat_link;
    while (next != NULL) {
        // 检查释放过期
        if (next->expire_time < current_sec) {
            next = next->next;
            continue;
        }
        // 检查协议
        if (next->protocol != info->protocol && next->protocol != IPPROTO_UDP && next->protocol != IPPROTO_TCP) {
            next = next->next;
            continue;
        }
        // SNAT检查outdev
        if (next->nat_type == FILTER_SNAT && next->ip_info.outdev != info->outdev) {
            next = next->next;
            continue;
        }
        // DNAT检查indev
        if (next->nat_type == FILTER_DNAT && next->ip_info.indev != info->indev) {
            next = next->next;
            continue;
        }
        // UDP TCP需要同时检查ip与端口
        if (next->ip_info.saddr == info->saddr && next->ip_info.sport == info->sport && next->ip_info.daddr == info->daddr && next->ip_info.dport == info->dport) {
            break;
        }
        next = next->next;
    }
    if (next != NULL) {
        // 进行nat转换
        if (do_nat(next, info, skb) == 0) {
            next->expire_time = current_sec + EXPIRE_TIME;
            nat_format(next, nat_str, sizeof(nat_str));
            async_log(LOG_INFO, "[FILTER] [NAT_MATCH] %s", nat_str);
        }
        else {
            next = NULL;
        }
    }

    return next;
}

FilterNatNodeV4 *filter_nat2_match_v4(IpPackInfoV4 *info, struct sk_buff *skb) {
    char nat_str[DEFAULT_STR_SIZE];
    FilterNatNodeV4 *next;
    struct timespec64 current_time;
    u64 current_sec;
    if (info == NULL || skb == NULL) {
        return NULL;
    }

    // 获取当前时间
    ktime_get_real_ts64(&current_time);
    current_sec = current_time.tv_sec;
    next = nf_hook_nat_link;
    while (next != NULL) {
        // 检查释放过期
        if (next->expire_time < current_sec) {
            next = next->next;
            continue;
        }
        // 检查协议
        if (next->protocol != info->protocol && next->protocol != IPPROTO_UDP && next->protocol != IPPROTO_TCP) {
            next = next->next;
            continue;
        }
        // SNAT检查indev
        if (next->nat_type == FILTER_SNAT && next->ip_info.outdev != info->indev) {
            next = next->next;
            continue;
        }
        // DNAT检查outdev
        if (next->nat_type == FILTER_DNAT && next->ip_info.indev != info->outdev) {
            next = next->next;
            continue;
        }
        // UDP TCP需要同时检查ip与端口
        if (next->nat_type == FILTER_SNAT) {
            if (info->saddr == next->ip_info.daddr && info->sport == next->ip_info.dport && info->daddr == next->nataddr && info->dport == next->natport) {
                break;
            }
        }
        else if (next->nat_type == FILTER_DNAT) {
            if (info->saddr == next->nataddr && info->sport == next->natport && info->daddr == next->ip_info.saddr && info->dport == next->ip_info.sport) {
                break;
            }
        }
        next = next->next;
    }
    if (next != NULL) {
        // 进行nat转换
        if (do_nat2(next, info, skb) == 0) {
            next->expire_time = current_sec + EXPIRE_TIME;
            nat_format(next, nat_str, sizeof(nat_str));
            async_log(LOG_INFO, "[FILTER] [NAT_MATCH2] %s", nat_str);
        }
        else {
            next = NULL;
        }
    }

    return next;
}

int filter_nat_insert_v4(FilterRuleV4 *nat_rule, IpPackInfoV4 *info, struct sk_buff *skb) {
    char nat_str[DEFAULT_STR_SIZE];
    FilterNatNodeV4 *next;
    FilterNatNodeV4 *new_node;
    struct timespec64 current_time;
    unsigned short random_port;
    u64 current_sec;
    int ret;
    if (nat_rule == NULL ||info == NULL || skb == NULL) {
        return -1;
    }

    if (info->protocol != IPPROTO_UDP && info->protocol != IPPROTO_TCP) {
        return -1;
    }

    if (nat_rule->rule_type != FILTER_SNAT && nat_rule->rule_type != FILTER_DNAT) {
        return -1;
    }

    new_node = (FilterNatNodeV4 *)kmalloc(sizeof(FilterNatNodeV4), GFP_KERNEL);
    if (new_node == NULL) {
        return -1;
    }
    // 获取当前时间
    ktime_get_real_ts64(&current_time);
    current_sec = current_time.tv_sec;
    memcpy(&(new_node->ip_info), info, sizeof(new_node->ip_info));
    new_node->protocol = nat_rule->protocol;
    new_node->nat_type = nat_rule->rule_type;
    // 设置nat地址及端口
    new_node->nataddr = nat_rule->nataddr;
    if (ntohs(nat_rule->natport) != 0) {
        new_node->natport = nat_rule->natport;
    }
    else {
        do {
            get_random_bytes(&random_port, sizeof(random_port));
        } while (random_port < 1024);
        new_node->natport = htons(random_port);
    }
    // 设置过期时间
    new_node->expire_time = current_sec + EXPIRE_TIME;
    // 进行nat转换
    if (do_nat(new_node, info, skb) == 0) {
        // 插入到链表末尾
        if (nf_hook_nat_link == NULL) {
            nf_hook_nat_link = new_node;
        }
        else {
            next = nf_hook_nat_link;
            while (next->next != NULL) {
                next = next->next;
            }
            next->next = new_node;
        }
        nat_format(new_node, nat_str, sizeof(nat_str));
        async_log(LOG_INFO, "[FILTER] [NAT_NEW] %s", nat_str);
        ret = 0;
    }
    else {
        kfree(new_node);
        ret = -1;
    }

    return ret;
}

void filter_nat_clear_v4(FilterNatNodeV4 *nat_link) {
    FilterNatNodeV4 *rm_node;
    FilterNatNodeV4 *next;
    if (nat_link == NULL) {
        return;
    }

    next = nat_link;
    while (next != NULL) {
        rm_node = next;
        next = rm_node->next;
        kfree(rm_node);
    }
}

void filter_nat_dump_v4(FilterNatNodeV4 *nat_link, const char *tmpfile) {
    char nat_str[DEFAULT_STR_SIZE];
    FilterNatNodeV4 *next;
    struct nl_msg_struct *msg;
    NatConfig *msg_conf;
    struct file *fp;
    if (tmpfile == NULL) {
        return;
    }
    fp = filp_open(tmpfile, O_WRONLY | O_CREAT, 0600);
    if (IS_ERR(fp)) {
        return;
    }
    next = nat_link;
    msg = (struct nl_msg_struct *)kmalloc(NL_MSG_SIZE(sizeof(NatConfig)), GFP_KERNEL);
    if (msg == NULL) {
        filp_close(fp, NULL);
        return;
    }
    msg->msg_type = NL_MSG_CONF;
    msg->msg_size = NL_MSG_SIZE(sizeof(NatConfig));
    msg_conf = (NatConfig *)NL_MSG_DATA(msg);
    msg_conf->config_type = CONF_NAT_DUMP;
    while (next != NULL) {
        nat_format(next, nat_str, sizeof(nat_str));
        kernel_write(fp, nat_str, strlen(nat_str), &fp->f_pos);
        kernel_write(fp, "\n", 1, &fp->f_pos);
        next = next->next;
    }
    filp_close(fp, NULL);
    // 回应用户态程序dump结束
    memset(&(msg_conf->conf_str), 0, sizeof(msg_conf->conf_str));
    nl_send_msg(msg);
    kfree(msg);
}

void filter_nat_config(NatConfig *conf) {
    // 获取写sem
    down_write(&nf_hook_nat_rwsem);
    switch (conf->config_type) {
        case CONF_NAT_CLEAR:
            async_log(LOG_WARNING, "[MANAGE] Clear nat connections");
            filter_nat_clear_v4(nf_hook_nat_link);
            nf_hook_nat_link = NULL;
            break;
        case CONF_NAT_DUMP:
            async_log(LOG_WARNING, "[MANAGE] Dump nat connections");
            filter_nat_dump_v4(nf_hook_nat_link, conf->conf_str);
            break;
    }
    // 释放写sem
    up_write(&nf_hook_nat_rwsem);
}


void filter_nat_updater(struct timer_list *t) {
    struct timespec64 current_time;
    u64 current_sec;
    FilterNatNodeV4 *next;
    FilterNatNodeV4 *prev;
    char nat_str[DEFAULT_STR_SIZE];

    // 获取写sem
    down_write(&nf_hook_nat_rwsem);
    // 获取当前时间
    ktime_get_real_ts64(&current_time);
    current_sec = current_time.tv_sec;

    next = nf_hook_nat_link;
    prev = NULL;
    while (next != NULL) {
        if (next->expire_time < current_sec) {
            nat_format(next, nat_str, sizeof(nat_str));
            async_log(LOG_INFO, "[FILTER] [NAT_EXPIRED] %s", nat_str);
            // 过期移除
            if (prev == NULL) {
                nf_hook_nat_link = next->next;
                kfree(next);
                next = nf_hook_nat_link;
            }
            else {
                prev->next = next->next;
                kfree(next);
                next = prev->next;
            }
            continue;
        }
        prev = next;
        next = next->next;
    }
    
    // 释放写sem
    up_write(&nf_hook_nat_rwsem);
    // 设置下一次定时任务
    mod_timer(t, jiffies + msecs_to_jiffies(UPDATE_TIME));
}