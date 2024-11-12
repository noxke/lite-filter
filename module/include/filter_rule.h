#ifndef __FILTER_RULE_H__ // __FILTER_RULE_H__
#define __FILTER_RULE_H__
// 过滤器规则接口

#define DEFAULT_STR_SIZE 256
// 默认过期时间300s
#define EXPIRE_TIME 300
// 默认更新时间5000ms
#define UPDATE_TIME 5000

typedef unsigned char u8;
typedef unsigned long long u64;

enum NL_HOOK_CHAIN {
    NF_HOOK_NONE = 0,
    NF_HOOK_PREROUTING = 1,
    NF_HOOK_LOCALIN = 2,
    NF_HOOK_FORWARD = 3,
    NF_HOOK_LOCALOUT = 4,
    NF_HOOK_POSTROUTING = 5,
    NF_HOOK_NAT = 6,
    NF_HOOK_MAX = 7,
};

enum FILTER_MATCH_FLAGS {
    FILTER_MATCH_INDEV =    0b0000001,
    FILTER_MATCH_OUTDEV =   0b0000010,
    FILTER_MATCH_PROTO =    0b0000100,
    FILTER_MATCH_SADDR =    0b0001000,
    FILTER_MATCH_DADDR =    0b0010000,
    FILTER_MATCH_SPORT =    0b0100000,
    FILTER_MATCH_DPORT =    0b1000000,
};

enum FILTER_RULES_TYPE {
    FILTER_NONE = 0,
    FILTER_ACCEPT = 1,  // 通过
    FILTER_DROP = 2,    // 丢弃
    FILTER_SNAT = 3,    // 原NAT转换
    FILTER_DNAT = 4,    // 目的NAT转换
    FILTER_MAX = 5,
};

// 连接状态枚举
enum FILTER_STATUS_ENUM {
    FILTER_STATUS_NONE = 0,
    FILTER_STATUS_ICMP = 1,
    FILTER_STATUS_UDP = 2,
    FILTER_STATUS_TCP_CLOSED = 10,
    FILTER_STATUS_TCP_SYN_SENT = 11,
    FILTER_STATUS_TCP_SYN_RECEIVED = 12,
    FILTER_STATUS_TCP_ESTABLISHED = 13,
    FILTER_STATUS_TCP_FIN_WAIT = 14,
    FILTER_STATUS_TCP_CLOSE_WAIT = 15,
    FILTER_STATUS_TCP_LAST_ACK = 16,
    FILTER_STATUS_TCP_TIME_WAIT = 17,
};

typedef struct {
    int indev;
    int outdev;
    __be32 saddr;
    __be32 daddr;
    unsigned char protocol;
    __be16 sport;
    __be16 dport;
} IpPackInfoV4;

typedef struct {
    int indev;
    int outdev;
    __be32 saddr;
    __be32 daddr;
    u8 sprefixlen;
    u8 dprefixlen;
    unsigned char protocol;
    __be16 sport;
    __be16 dport;
    unsigned int match_flags;
    unsigned int rule_type;
    __be32 nataddr;
    __be16 natport;
} FilterRuleV4;

typedef struct {
    int config_type;
    int hook_chain;
    int index;
    FilterRuleV4 rule;
    char rule_str[DEFAULT_STR_SIZE];
} RuleConfig;

typedef struct _FilterNodeV4 {
    RuleConfig rule_conf;
    struct _FilterNodeV4 *next;
} FilterNodeV4;

typedef struct {
    int config_type;
    char conf_str[DEFAULT_STR_SIZE];
} ConnConfig;

typedef struct _FilterConnNodeV4 {
    IpPackInfoV4 ip_info;
    unsigned char protocol;
    unsigned char status;
    u64 expire_time;
    struct _FilterConnNodeV4 *next;
} FilterConnNodeV4;

typedef struct {
    int config_type;
    char conf_str[DEFAULT_STR_SIZE];
} NatConfig;

typedef struct _FilterNatNodeV4 {
    IpPackInfoV4 ip_info;
    __be32 nataddr;
    __be16 natport;
    u64 expire_time;
    struct _FilterNatNodeV4 *next;
} FilterNatNodeV4;

#endif // __FILTER_RULE_H__