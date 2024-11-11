#ifndef __FILTER_RULE_UTILS_H__ // __FILTER_RULE_UTILS_H__
#define __FILTER_RULE_UTILS_H__
// 过滤器规则接口

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "filter_rule.h"

void get_ip_pack_info_v4(struct sk_buff *skb, IpPackInfoV4 *info);

RuleConfig *filter_rule_match_v4(FilterNodeV4 *rule_link, IpPackInfoV4 *info);
void filter_rule_matched_log(RuleConfig *matched_rule, IpPackInfoV4 *info);

FilterNodeV4 *filter_rule_insert_v4(FilterNodeV4 *rule_link, int index, RuleConfig *conf);
FilterNodeV4 *filter_rule_remove_v4(FilterNodeV4 *rule_link, int index);

void filter_rule_clear_v4(FilterNodeV4 *rule_link);

extern void filter_rule_config(RuleConfig *conf);

#endif // __FILTER_RULE_UTILS_H__