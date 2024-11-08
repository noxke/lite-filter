#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/mutex.h>

#include "log_utils.h"
#include "netfilter_hook.h"
#include "filter_rule_utils.h"

// Hook function for PREROUTING chain
unsigned int hook_prerouting_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;
    IpPackInfoV4 info;
    RuleConfig *matched_rule;

    memset(&info, 0, sizeof(info));
    // 解析ip数据包信息
    get_ip_pack_info_v4(skb, &info);
    if (indev != 0) {
        info.indev = indev->ifindex;
    }
    else {
        info.indev = -1;
    }
    if (outdev != 0) {
        info.outdev = outdev->ifindex;
    }
    else {
        info.outdev = -1;
    }
    
    // 匹配PREROUTING链表
    matched_rule = filter_rule_match_v4(nf_hook_table[NF_HOOK_PREROUTING].rule_link, &info);
    if (matched_rule != NULL && matched_rule->rule.match_flags != 0) {
        filter_rule_matched_log(matched_rule, &info);
    }

    return NF_ACCEPT;
}

// Hook function for INPUT chain
unsigned int hook_input_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;

    return NF_ACCEPT;
}

// Hook function for FORWARD chain
unsigned int hook_forward_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;

    return NF_ACCEPT;
}

// Hook function for OUTPUT chain
unsigned int hook_output_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;

    return NF_ACCEPT;
}

// Hook function for POSTROUTING chain
unsigned int hook_postrouting_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;

    return NF_ACCEPT;
}

struct nf_hook_table_struct nf_hook_table[NF_HOOK_MAX] = {
    {
        .rule_link = NULL,
        .chain_name = "NONE",
    },
    {
        .rule_link = NULL,
        .chain_name = "PREROUTING",
        .ops = {
            .hook = hook_prerouting_func,
            .pf = PF_INET,
            .hooknum = NF_INET_PRE_ROUTING,
            .priority = NF_IP_PRI_FIRST,
        },
    },
    {
        .rule_link = NULL,
        .chain_name = "LOCALIN",
        .ops = {
            .hook = hook_input_func,
            .pf = PF_INET,
            .hooknum = NF_INET_LOCAL_IN,
            .priority = NF_IP_PRI_FIRST,
        },
    },
    {
        .rule_link = NULL,
        .chain_name = "FORWARD",
        .ops = {
            .hook = hook_forward_func,
            .pf = PF_INET,
            .hooknum = NF_INET_FORWARD,
            .priority = NF_IP_PRI_FIRST,
        },
    },
    {
        .rule_link = NULL,
        .chain_name = "LOCALOUT",
        .ops = {
            .hook = hook_output_func,
            .pf = PF_INET,
            .hooknum = NF_INET_LOCAL_OUT,
            .priority = NF_IP_PRI_FIRST,
        },
    },
    {
        .rule_link = NULL,
        .chain_name = "POSTROUTING",
        .ops = {
            .hook = hook_postrouting_func,
            .pf = PF_INET,
            .hooknum = NF_INET_POST_ROUTING,
            .priority = NF_IP_PRI_FIRST,
        },
    },
    {
        .rule_link = NULL,
        .chain_name = "NAT",
    },
};


int nf_hook_init() {
    int i;
    // 初始化锁
    for (i = NF_HOOK_NONE+1; i < NF_HOOK_MAX; i++) {
        mutex_init(&(nf_hook_table[i].chain_mutex));
    }
    // 注册钩子
    for (i = NF_HOOK_NONE+1; i < NF_HOOK_NAT; i++) {
        nf_register_net_hook(&init_net, &(nf_hook_table[i].ops));
    }
    return 0;
}

void nf_hook_exit() {
    int i;
    // 卸载钩子
    for (i = NF_HOOK_NONE+1; i < NF_HOOK_NAT; i++) {
        nf_unregister_net_hook(&init_net, &(nf_hook_table[i].ops));
    }
    // 销毁锁
    for (i = NF_HOOK_NONE+1; i < NF_HOOK_MAX; i++) {
        mutex_destroy(&(nf_hook_table[i].chain_mutex));
    }
}