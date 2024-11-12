#ifndef __NETFILTER_HOOK_H__ // __NETFILTER_HOOK_H__
#define __NETFILTER_HOOK_H__
// netfilter接口

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/semaphore.h>
#include "filter_rule_utils.h"

struct nf_hook_table_struct {
    FilterNodeV4 *rule_link;
    struct rw_semaphore rw_sem;      // 信号量，用于避免读时写
    const char *chain_name;
    struct nf_hook_ops ops;
};

extern FilterConnNodeV4 *nf_hook_conn_link;
extern struct rw_semaphore nf_hook_conn_rwsem;
extern FilterNatNodeV4 *nf_hook_nat_link;
extern struct rw_semaphore nf_hook_nat_rwsem;

extern struct nf_hook_table_struct nf_hook_table[NF_HOOK_MAX];

extern int nf_hook_init(void);
extern void nf_hook_exit(void);

#endif // __NETFILTER_HOOK_H__