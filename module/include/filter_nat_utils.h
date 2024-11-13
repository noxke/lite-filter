#ifndef __FILTER_NAT_UTILS_H__ // __FILTER_NAT_UTILS_H__
#define __FILTER_NAT_UTILS_H__
// NAT连接状态接口

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/timer.h>

#include "filter_rule.h"

// NAT发送报文匹配
FilterNatNodeV4 *filter_nat_match_v4(IpPackInfoV4 *info, struct sk_buff *skb);
// NAT接收报文匹配
FilterNatNodeV4 *filter_nat2_match_v4(IpPackInfoV4 *info, struct sk_buff *skb);

int filter_nat_insert_v4(FilterRuleV4 *nat_rule, IpPackInfoV4 *info, struct sk_buff *skb);

void filter_nat_clear_v4(FilterNatNodeV4 *nat_link);

extern void filter_nat_config(NatConfig *conf);

extern void filter_nat_updater(struct timer_list *t);

#endif // __FILTER_NAT_UTILS_H__