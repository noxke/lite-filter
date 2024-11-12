#ifndef __CONF_UTILS_H__ // __CONF_UTILS_H__
#define __CONF_UTILS_H__
// 配置接口
#include <netinet/ip.h>
#include <linux/types.h>
#include <pthread.h>

#include "netlink_msg.h"
#include "filter_rule.h"

extern int nl_msg_config_handler(struct nl_msg_struct *msg);

enum {
    CONF_LOG_SET = 1,   // 日志配置
    CONF_LOG_GET = 2,   // 日志配置
    CONF_RULE_CLEAR = 10, // 清空规则链
    CONF_RULE_INSERT = 11,   // 添加规则
    CONF_RULE_REMOVE = 12,   // 移除规则
    CONF_RULE_DUMP = 13, // 读取规则输出
    CONF_CONN_CLEAR = 20, // 清除连接表
    CONF_CONN_DUMP = 21, // 读取连接表
    CONF_NAT_CLEAR = 30, // 清除NAT连接表
    CONF_NAT_DUMP = 31, // 读取NAT连接表
};

#define LOG_FILENAME_SIZE 256

typedef struct {
    int config_type;
    int log_level;
    int log_kprint_level;
    char log_file[LOG_FILENAME_SIZE];
}LogConfig;

int config_log_set(LogConfig *conf);
int config_log_get(LogConfig *conf);

int config_rule_clear(int hook_chain);
int config_rule_insert(RuleConfig *conf, int index);
int config_rule_remove(int hook_chain, int index);
int config_rule_dump(int hook_chain, FILE *fp, int with_index);

int config_conn_clear();
int config_conn_dump();

int config_nat_clear();
int config_nat_dump();
#endif // __CONF_UTILS_H__