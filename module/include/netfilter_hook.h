#ifndef __NETFILTER_HOOK_H__ // __NETFILTER_HOOK_H__
#define __NETFILTER_HOOK_H__
// netfilter接口

#include "filter_rule_utils.h"

extern FilterNodeV4 *hook_rule_link[5];

extern int nf_hook_init(void);
extern void nf_hook_exit(void);

#endif // __NETFILTER_HOOK_H__