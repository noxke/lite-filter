#ifndef __FILTER_RULE_UTILS_H__ // __FILTER_RULE_UTILS_H__
#define __FILTER_RULE_UTILS_H__
// 过滤器规则接口

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "filter_rule.h"


static inline bool addr4_amtch(__be32 a1, __be32 a2, u8 prefixlen) {
    if (prefixlen == 0) {
        return true;
    }
    return !((a1 ^ a2) & htonl(~0UL << (32 - prefixlen)));
}

void get_ip_pack_info_v4(struct sk_buff *skb, IpPackInfoV4 *info);

FilterRuleV4 *filter_rule_match_v4(FilterNodeV4 *rule_link, IpPackInfoV4 *info);

FilterNodeV4 *filter_rule_insert_v4(FilterNodeV4 *rule_link, int index, FilterRuleV4 *rule);
FilterNodeV4 *filter_rule_remove_v4(FilterNodeV4 *rule_link, int index);

extern void filter_rule_config(RuleConfig *conf);

#endif // __FILTER_RULE_UTILS_H__