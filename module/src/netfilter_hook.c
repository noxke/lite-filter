#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/semaphore.h>
#include <linux/timer.h>

#include "log_utils.h"
#include "netfilter_hook.h"
#include "filter_rule_utils.h"
#include "filter_conn_utils.h"

// Hook function for PREROUTING chain
unsigned int hook_prerouting_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;
    IpPackInfoV4 info;
    RuleConfig *matched_rule;
    FilterConnNodeV4 *matched_conn;
    int action = NF_ACCEPT;

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

    // 先在状态表内进行匹配
    // 获取读sem
    down_read(&nf_hook_conn_rwsem);
    matched_conn = filter_conn_match_v4(&info, skb);
    // // 释放读sem
    up_read(&nf_hook_conn_rwsem);
    // 匹配成功则直接放行报文
    if (matched_conn != NULL) {
        return NF_ACCEPT;
    }

    // 获取读sem
    down_read(&(nf_hook_table[NF_HOOK_PREROUTING].rw_sem));
    
    // 匹配PREROUTING链表
    matched_rule = filter_rule_match_v4(nf_hook_table[NF_HOOK_PREROUTING].rule_link, &info);
    if (matched_rule != NULL && matched_rule->rule.match_flags != 0) {
        filter_rule_matched_log(matched_rule, &info);
        if (matched_rule->rule.rule_type == FILTER_ACCEPT) {
            action = NF_ACCEPT;
            // 如果规则链中匹配成功，则添加新连接
            // 获取写sem
            down_write(&nf_hook_conn_rwsem);
            filter_conn_insert_v4(&info, skb);
            // 释放写sem
            up_write(&nf_hook_conn_rwsem);
        }
        else if (matched_rule->rule.rule_type == FILTER_DROP) {
            action = NF_DROP;
        }
    }

    // 释放读sem
    up_read(&(nf_hook_table[NF_HOOK_PREROUTING].rw_sem));

    return action;
}

// Hook function for INPUT chain
unsigned int hook_input_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;
    IpPackInfoV4 info;
    RuleConfig *matched_rule;
    int action = NF_ACCEPT;

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

    // 获取读sem
    down_read(&(nf_hook_table[NF_HOOK_LOCALIN].rw_sem));
    
    // 匹配LOCALIN链表
    matched_rule = filter_rule_match_v4(nf_hook_table[NF_HOOK_LOCALIN].rule_link, &info);
    if (matched_rule != NULL && matched_rule->rule.match_flags != 0) {
        filter_rule_matched_log(matched_rule, &info);
        if (matched_rule->rule.rule_type == FILTER_ACCEPT) {
            action = NF_ACCEPT;
        }
        else if (matched_rule->rule.rule_type == FILTER_DROP) {
            action = NF_DROP;
        }
    }

    // 释放读sem
    up_read(&(nf_hook_table[NF_HOOK_LOCALIN].rw_sem));

    return action;
}

// Hook function for FORWARD chain
unsigned int hook_forward_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;
    IpPackInfoV4 info;
    RuleConfig *matched_rule;
    int action = NF_ACCEPT;

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
    
    // 获取读sem
    down_read(&(nf_hook_table[NF_HOOK_FORWARD].rw_sem));

    // 匹配FORWARD链表
    matched_rule = filter_rule_match_v4(nf_hook_table[NF_HOOK_FORWARD].rule_link, &info);
    if (matched_rule != NULL && matched_rule->rule.match_flags != 0) {
        filter_rule_matched_log(matched_rule, &info);
        if (matched_rule->rule.rule_type == FILTER_ACCEPT) {
            action = NF_ACCEPT;
        }
        else if (matched_rule->rule.rule_type == FILTER_DROP) {
            action = NF_DROP;
        }
    }

    // 释放读sem
    up_read(&(nf_hook_table[NF_HOOK_FORWARD].rw_sem));

    return action;
}

// Hook function for OUTPUT chain
unsigned int hook_output_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;
    IpPackInfoV4 info;
    RuleConfig *matched_rule;
    int action = NF_ACCEPT;

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
    
    // 获取读sem
    down_read(&(nf_hook_table[NF_HOOK_LOCALOUT].rw_sem));

    // 匹配LOCALOUT链表
    matched_rule = filter_rule_match_v4(nf_hook_table[NF_HOOK_LOCALOUT].rule_link, &info);
    if (matched_rule != NULL && matched_rule->rule.match_flags != 0) {
        filter_rule_matched_log(matched_rule, &info);
        if (matched_rule->rule.rule_type == FILTER_ACCEPT) {
            action = NF_ACCEPT;
        }
        else if (matched_rule->rule.rule_type == FILTER_DROP) {
            action = NF_DROP;
        }
    }

    // 释放读sem
    up_read(&(nf_hook_table[NF_HOOK_LOCALOUT].rw_sem));

    return action;
}

// Hook function for POSTROUTING chain
unsigned int hook_postrouting_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;
    IpPackInfoV4 info;
    RuleConfig *matched_rule;
    int action = NF_ACCEPT;

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

    // 获取读sem
    down_read(&(nf_hook_table[NF_HOOK_POSTROUTING].rw_sem));
    
    // 匹配POSTROUTING链表
    matched_rule = filter_rule_match_v4(nf_hook_table[NF_HOOK_POSTROUTING].rule_link, &info);
    if (matched_rule != NULL && matched_rule->rule.match_flags != 0) {
        filter_rule_matched_log(matched_rule, &info);
        if (matched_rule->rule.rule_type == FILTER_ACCEPT) {
            action = NF_ACCEPT;
        }
        else if (matched_rule->rule.rule_type == FILTER_DROP) {
            action = NF_DROP;
        }
    }

    // 释放读sem
    up_read(&(nf_hook_table[NF_HOOK_POSTROUTING].rw_sem));

    return action;
}

struct nf_hook_table_struct nf_hook_table[NF_HOOK_MAX] = {
    {
        .chain_name = "NONE",
    },
    {
        .chain_name = "PREROUTING",
        .ops = {
            .hook = hook_prerouting_func,
            .pf = PF_INET,
            .hooknum = NF_INET_PRE_ROUTING,
            .priority = NF_IP_PRI_FIRST,
        },
    },
    {
        .chain_name = "LOCALIN",
        .ops = {
            .hook = hook_input_func,
            .pf = PF_INET,
            .hooknum = NF_INET_LOCAL_IN,
            .priority = NF_IP_PRI_FIRST,
        },
    },
    {
        .chain_name = "FORWARD",
        .ops = {
            .hook = hook_forward_func,
            .pf = PF_INET,
            .hooknum = NF_INET_FORWARD,
            .priority = NF_IP_PRI_FIRST,
        },
    },
    {
        .chain_name = "LOCALOUT",
        .ops = {
            .hook = hook_output_func,
            .pf = PF_INET,
            .hooknum = NF_INET_LOCAL_OUT,
            .priority = NF_IP_PRI_FIRST,
        },
    },
    {
        .chain_name = "POSTROUTING",
        .ops = {
            .hook = hook_postrouting_func,
            .pf = PF_INET,
            .hooknum = NF_INET_POST_ROUTING,
            .priority = NF_IP_PRI_FIRST,
        },
    },
    {
        .chain_name = "NAT",
    },
};

FilterConnNodeV4 *nf_hook_conn_link;
struct rw_semaphore nf_hook_conn_rwsem;
FilterNatNodeV4 *nf_hook_nat_link;
struct rw_semaphore nf_hook_nat_rwsem;
static struct timer_list status_update_timer;

int nf_hook_init() {
    int i;
    // 初始化nf_hook_table
    for (i = NF_HOOK_NONE+1; i < NF_HOOK_MAX; i++) {
        nf_hook_table[i].rule_link = NULL;
        // 初始化信号量
        init_rwsem(&(nf_hook_table[i].rw_sem));
    }
    nf_hook_conn_link = NULL;
    init_rwsem(&nf_hook_conn_rwsem);
    nf_hook_nat_link = NULL;
    init_rwsem(&nf_hook_nat_rwsem);
    // 注册钩子
    for (i = NF_HOOK_NONE+1; i < NF_HOOK_NAT; i++) {
        nf_register_net_hook(&init_net, &(nf_hook_table[i].ops));
    }
    // 创建状态更新任务
    timer_setup(&status_update_timer, filter_conn_updater, 0);
    mod_timer(&status_update_timer, jiffies + msecs_to_jiffies(UPDATE_TIME));
    return 0;
}

void nf_hook_exit() {
    int i;
    // 销毁状态更新任务
    del_timer(&status_update_timer);
    // 卸载钩子
    for (i = NF_HOOK_NONE+1; i < NF_HOOK_NAT; i++) {
        nf_unregister_net_hook(&init_net, &(nf_hook_table[i].ops));
    }
    // 清除所有的规则链
    for (i = NF_HOOK_NONE+1; i < NF_HOOK_MAX; i++) {
        filter_rule_clear_v4(nf_hook_table[i].rule_link);
        nf_hook_table[i].rule_link = NULL;
    }
    filter_conn_clear_v4(nf_hook_conn_link);
    nf_hook_conn_link = NULL;
    nf_hook_nat_link = NULL;
}