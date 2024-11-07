#ifndef __NETFILTER_HOOK_H__ // __NETFILTER_HOOK_H__
#define __NETFILTER_HOOK_H__
// netfilter接口

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "linux/mutex.h"
#include "filter_rule_utils.h"

struct nf_hook_table_struct {
    FilterNodeV4 *rule_link;
    struct mutex chain_mutex;
    const char *chain_name;
    struct nf_hook_ops ops;
};

extern struct nf_hook_table_struct nf_hook_table[NF_HOOK_MAX];

extern int nf_hook_init(void);
extern void nf_hook_exit(void);

#endif // __NETFILTER_HOOK_H__