#ifndef __FILTER_RULE_H__ // __FILTER_RULE_H__
#define __FILTER_RULE_H__
// 过滤器规则接口

#define MAX_RULE_STR_SIZE 256

typedef unsigned char u8;

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

typedef struct _FilterNodeV4 {
    FilterRuleV4 rule;
    struct _FilterNodeV4 *next;
} FilterNodeV4;

typedef struct {
    int config_type;
    int hook_chain;
    int index;
    FilterRuleV4 rule;
    char rule_str[MAX_RULE_STR_SIZE];
}RuleConfig;


#endif // __FILTER_RULE_H__