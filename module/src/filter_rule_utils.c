#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "module_utils.h"
#include "netfilter_hook.h"
#include "filter_rule_utils.h"

void get_ip_pack_info_v4(struct sk_buff *skb, IpPackInfoV4 *info) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    if (skb == NULL || info == NULL) {
        return;
    }
    ip_header = ip_hdr(skb);
    info->protocol = ip_header->protocol;
    info->saddr = ip_header->saddr;
    info->daddr = ip_header->daddr;
    switch (info->protocol) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_TCP:
            tcp_header = tcp_hdr(skb);
            info->sport = tcp_header->source;
            info->dport = tcp_header->dest;
            break;
        case IPPROTO_UDP:
            udp_header = udp_hdr(skb);
            info->sport = udp_header->source;
            info->dport = udp_header->dest;
            break;
        default:
            break;
    }
}

FilterRuleV4 *filter_rule_match_v4(FilterNodeV4 *rule_link, IpPackInfoV4 *info) {
    FilterRuleV4 *rule;
    FilterNodeV4 *rule_next;
    if (rule_link == NULL || info == NULL) {
        return NULL;
    }
    rule_next = rule_link;
    while (rule_next != NULL) {
        rule = &(rule_next->rule);
        rule_next = rule_next->next;
        if (((rule->match_flags & FILTER_MATCH_INDEV) != 0) && (rule->indev != info->indev)) {
            continue;
        }
        if (((rule->match_flags & FILTER_MATCH_OUTDEV) != 0) && (rule->outdev != info->outdev)) {
            continue;
        }
        if (((rule->match_flags & FILTER_MATCH_PROTO) != 0) && (rule->protocol != info->protocol)) {
            continue;
        }
        if (((rule->match_flags & FILTER_MATCH_SADDR) != 0) && addr4_amtch(rule->saddr, info->saddr, rule->sprefixlen)) {
            continue;
        }
        if (((rule->match_flags & FILTER_MATCH_DADDR) != 0) && addr4_amtch(rule->daddr, info->daddr, rule->dprefixlen)) {
            continue;
        }
        if (((rule->match_flags & FILTER_MATCH_SPORT) != 0) && (rule->sport != info->sport)) {
            continue;
        }
        if (((rule->match_flags & FILTER_MATCH_DPORT) != 0) && (rule->dport != info->dport)) {
            continue;
        }
        return rule;
    }
    return NULL;
}

FilterNodeV4 *filter_rule_insert_v4(FilterNodeV4 *rule_link, int index, FilterRuleV4 *rule) {
    FilterNodeV4 *prev;
    FilterNodeV4 *next;
    FilterNodeV4 *new_node;
    int idx;
    if (rule == NULL) {
        return rule_link;
    }
    new_node = (FilterNodeV4 *)kmalloc(sizeof(FilterNodeV4), GFP_KERNEL);
    if (new_node == NULL) {
        return rule_link;
    }
    memcpy(&(new_node->rule), rule, sizeof(FilterRuleV4));
    prev = NULL;
    next = rule_link;
    idx = 0;
    while (next != NULL && ((idx++ < index) || (index == -1))) {
        prev = next;
        next = next->next;
    }
    new_node->next = next;
    if (prev != NULL) {
        prev->next = new_node;
        return rule_link;
    }
    return new_node;
}
FilterNodeV4 *filter_rule_remove_v4(FilterNodeV4 *rule_link, int index) {
    FilterNodeV4 *prev;
    FilterNodeV4 *rm_node;
    int idx;
    prev = NULL;
    rm_node = rule_link;
    idx = 0;
    while (rm_node != NULL && ((idx++ < index) || (index == -1))) {
        if (rm_node->next == NULL) {
            break;
        }
        prev = rm_node;
        rm_node = rm_node->next;
    }
    if (prev == NULL) {
        if (rm_node == NULL) {
            return NULL;
        }
        prev = rm_node->next;
        kfree(rm_node);
        return prev;
    }
    prev->next = rm_node->next;
    kfree(rm_node);
    return rule_link;
}

void filter_rule_clear_v4(RuleConfig *conf) {
    FilterNodeV4 *rm_node;
    FilterNodeV4 *next;
    if (conf->hook_chain < NF_HOOK_PREROUTING || conf->hook_chain > NF_HOOK_POSTROUTING) {
        return;
    }
    next = hook_rule_link[conf->hook_chain];
    while (next != NULL) {
        rm_node = next;
        next = rm_node->next;
        kfree(rm_node);
    }
}

void filter_rule_dump_v4(RuleConfig *conf) {
    FilterNodeV4 *rm_node;
    FilterNodeV4 *next;
    if (conf->hook_chain < NF_HOOK_PREROUTING || conf->hook_chain > NF_HOOK_POSTROUTING) {
        return;
    }
}

void filter_rule_config(RuleConfig *conf) {
    switch (conf->config_type) {
        case CONF_RULE_CLEAR:
            filter_rule_clear_v4(conf);
            break;
        case CONF_RULE_INSERT:
            break;
        case CONF_RULE_REMOVE:
            break;
        case CONF_RULE_DUMP:
            filter_rule_dump_v4(conf);
            break;
    }
}