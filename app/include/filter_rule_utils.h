#ifndef __FILTER_RULE_UTILS_H__ // __FILTER_RULE_UTILS_H__
#define __FILTER_RULE_UTILS_H__
// 过滤器规则接口

#include <netinet/ip.h>
#include <linux/types.h>

#include "filter_rule.h"
#include "netlink_msg.h"

int get_interface_index(const char *if_name);
int get_interface_name(int if_index, char *if_name, int name_size);
int get_interface_address(int ifindex, struct in_addr *addr);

extern int rule_parser(const char *rule_str, RuleConfig *rule);
extern int rule_format(RuleConfig *rule, char *buf, int buf_size);
extern int nl_msg_config_handler(struct nl_msg_struct *msg);

#endif // __FILTER_RULE_UTILS_H__