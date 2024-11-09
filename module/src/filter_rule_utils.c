#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/mutex.h>

#include "log_utils.h"
#include "netlink_msg.h"
#include "netlink_utils.h"
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

int addr4_amtch(__be32 a1, __be32 a2, u8 prefixlen) {
    if (prefixlen == 0) {
        return 0;
    }
    if (((a1 ^ a2) & htonl(~0UL << (32 - prefixlen))) == 0) {
        return 0;
    }
    return -1;
}

RuleConfig *filter_rule_match_v4(FilterNodeV4 *rule_link, IpPackInfoV4 *info) {
    FilterNodeV4 *rule_next;
    RuleConfig *rule_conf;
    FilterRuleV4 *rule;
    if (rule_link == NULL || info == NULL) {
        return NULL;
    }
    rule_next = rule_link;
    while (rule_next != NULL) {
        rule_conf = &(rule_next->rule_conf);
        rule = &(rule_conf->rule);
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
        if (((rule->match_flags & FILTER_MATCH_SADDR) != 0) && addr4_amtch(rule->saddr, info->saddr, rule->sprefixlen) != 0) {
            continue;
        }
        if (((rule->match_flags & FILTER_MATCH_DADDR) != 0) && addr4_amtch(rule->daddr, info->daddr, rule->dprefixlen) != 0) {
            continue;
        }
        if (((rule->match_flags & FILTER_MATCH_SPORT) != 0) && (rule->sport != info->sport)) {
            continue;
        }
        if (((rule->match_flags & FILTER_MATCH_DPORT) != 0) && (rule->dport != info->dport)) {
            continue;
        }
        return rule_conf;
    }
    return NULL;
}

void filter_rule_matched_log(RuleConfig *matched_rule, IpPackInfoV4 *info) {
    const char *action;
    if (matched_rule == NULL || info == NULL) {
        return;
    }
    if (matched_rule->rule.rule_type == FILTER_ACCEPT) {
        action = "ACCEPT";
    }
    else if (matched_rule->rule.rule_type == FILTER_DROP) {
        action = "DROP";
    }
    else {
        return;
    }
    switch (info->protocol) {
        case IPPROTO_ICMP:
            async_log(LOG_INFO, "Rule matched: [%s] [ICMP] [%pI4->%pI4] %s", action, &(info->saddr), &(info->daddr), matched_rule->rule_str);
            break;
        case IPPROTO_TCP:
            async_log(LOG_INFO, "Rule matched: [%s] [TCP] [%pI4:%hu->%pI4:%hu] %s", action, &(info->saddr), ntohs(info->sport), &(info->daddr), ntohs(info->dport), matched_rule->rule_str);
            break;
        case IPPROTO_UDP:
            async_log(LOG_INFO, "Rule matched: [%s] [UDP] [%pI4:%hu->%pI4:%hu] %s", action, &(info->saddr), ntohs(info->sport), &(info->daddr), ntohs(info->dport), matched_rule->rule_str);
            break;
    }
}

FilterNodeV4 *filter_rule_insert_v4(FilterNodeV4 *rule_link, int index, RuleConfig *conf) {
    FilterNodeV4 *prev;
    FilterNodeV4 *next;
    FilterNodeV4 *new_node;
    int idx;
    if (conf == NULL) {
        return rule_link;
    }
    new_node = (FilterNodeV4 *)kmalloc(sizeof(FilterNodeV4), GFP_KERNEL);
    if (new_node == NULL) {
        return rule_link;
    }
    memcpy(&(new_node->rule_conf), conf, sizeof(new_node->rule_conf));
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

void filter_rule_clear_v4(FilterNodeV4 *rule_link) {
    FilterNodeV4 *rm_node;
    FilterNodeV4 *next;
    if (rule_link == NULL) {
        return;
    }
    next = rule_link;
    while (next != NULL) {
        rm_node = next;
        next = rm_node->next;
        kfree(rm_node);
    }
}

void filter_rule_dump_v4(FilterNodeV4 *rule_link, int hook_chain, const char *tmpfile) {
    FilterNodeV4 *next;
    struct nl_msg_struct *msg;
    RuleConfig *msg_conf;
    int idx = 0;
    struct file *fp;
    if (tmpfile == NULL) {
        return;
    }
    fp = filp_open(tmpfile, O_WRONLY | O_CREAT, 0600);
    if (IS_ERR(fp)) {
        return;
    }
    next = rule_link;
    msg = (struct nl_msg_struct *)kmalloc(NL_MSG_SIZE(sizeof(RuleConfig)), GFP_KERNEL);
    if (msg == NULL) {
        return;
    }
    msg->msg_type = NL_MSG_CONF;
    msg->msg_size = NL_MSG_SIZE(sizeof(RuleConfig));
    msg_conf = (RuleConfig *)NL_MSG_DATA(msg);
    msg_conf->config_type = CONF_RULE_DUMP;
    msg_conf->hook_chain = hook_chain;
    while (next != NULL) {
        msg_conf->index = idx;
        kernel_write(fp, &(next->rule_conf.rule), sizeof(FilterRuleV4), &fp->f_pos);
        next = next->next;
        idx += 1;
    }
    filp_close(fp, NULL);
    // 发送-1结束
    msg_conf->index = idx;
    memset(&(msg_conf->rule), 0, sizeof(FilterRuleV4));
    nl_send_msg(msg);
    kfree(msg);
}

void filter_rule_config(RuleConfig *conf) {
    int index;
    FilterNodeV4 *rule_link;
    const char *chain_name;
    struct mutex *chain_mutex;
    if (conf->hook_chain <= NF_HOOK_NONE || conf->hook_chain >= NF_HOOK_MAX) {
        return;
    }
    index = conf->index;
    rule_link = nf_hook_table[conf->hook_chain].rule_link;
    chain_name = nf_hook_table[conf->hook_chain].chain_name;
    chain_mutex = &(nf_hook_table[conf->hook_chain].chain_mutex);
    mutex_lock(chain_mutex);
    switch (conf->config_type) {
        case CONF_RULE_CLEAR:
            async_log(LOG_WARNING, "Clear rules in %s", chain_name);
            filter_rule_clear_v4(rule_link);
            nf_hook_table[conf->hook_chain].rule_link = NULL;
            break;
        case CONF_RULE_INSERT:
            async_log(LOG_WARNING, "Insert rule to %s idx=%d: %s", chain_name, index, conf->rule_str);
            rule_link = filter_rule_insert_v4(rule_link, index, conf);
            nf_hook_table[conf->hook_chain].rule_link = rule_link;
            break;
        case CONF_RULE_REMOVE:
            async_log(LOG_WARNING, "Remove rule from %s idx=%d: %s", chain_name, index, conf->rule_str);
            rule_link = filter_rule_remove_v4(rule_link, index);
            nf_hook_table[conf->hook_chain].rule_link = rule_link;
            break;
        case CONF_RULE_DUMP:
            async_log(LOG_WARNING, "Dump rules in %s", chain_name);
            filter_rule_dump_v4(rule_link, conf->hook_chain, conf->rule_str);
            break;
    }
    mutex_unlock(chain_mutex);
}