#ifndef __MODULE_UTILS_H__ // __MODULE_UTILS_H__
#define __MODULE_UTILS_H__
// 模块中间接口

#include "netlink_msg.h"

enum {
    CONF_LOG_SET = 1,   // 日志配置
    CONF_LOG_GET = 2,   // 日志配置
    CONF_RULE_CLEAR = 10, // 清空规则链
    CONF_RULE_INSERT = 11,   // 添加规则
    CONF_RULE_REMOVE = 12,   // 移除规则
    CONF_RULE_DUMP = 13, // 读取规则输出
    CONF_CONN_CLEAR = 20, // 清除状态表
    CONF_CONN_DUMP = 21, // 读取状态表
    CONF_NAT_CLEAR = 30, // 清除NAT连接表
    CONF_NAT_DUMP = 31, // 读取NAT连接表
};

extern int nl_msg_config_handler(struct nl_msg_struct *msg);

#endif // __MODULE_UTILS_H__