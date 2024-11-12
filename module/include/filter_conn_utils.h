#ifndef __FILTER_CONN_UTILS_H__ // __FILTER_CONN_UTILS_H__
#define __FILTER_CONN_UTILS_H__
// 过滤器连接状态接口

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/timer.h>

#include "filter_rule.h"

#define CONN_DROP ((FilterConnNodeV4 *)-1)

FilterConnNodeV4 *filter_conn_match_v4(IpPackInfoV4 *info, struct sk_buff *skb);

int filter_conn_insert_v4(IpPackInfoV4 *info, struct sk_buff *skb);

void filter_conn_clear_v4(FilterConnNodeV4 *conn_link);

extern void filter_conn_config(ConnConfig *conf);

extern void filter_conn_updater(struct timer_list *t);

#endif // __FILTER_CONN_UTILS_H__