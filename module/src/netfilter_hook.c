#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/netdevice.h>

#include "log_utils.h"
#include "netfilter_hook.h"
#include "filter_rule_utils.h"

FilterNodeV4 *hook_rule_link[5] = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};

// Hook function for PREROUTING chain
unsigned int hook_prerouting_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;

    if (indev != NULL && outdev != NULL) {
        async_log(LOG_INFO, "PREROUTING : %s -> %s", indev->name, outdev->name);
    }
    else if (indev != NULL && outdev == NULL) {
        async_log(LOG_INFO, "PREROUTING : %s ->", indev->name);
    }
    else if (indev == NULL && outdev != NULL) {
        async_log(LOG_INFO, "PREROUTING : -> %s", outdev->name);
    }
    else if (indev == NULL && outdev == NULL) {
        async_log(LOG_INFO, "PREROUTING : ->");
    }

    // Check if the incoming device is docker0
    if (indev && strcmp(indev->name, "docker0") == 0) {
        iph = ip_hdr(skb);
        
        if (iph) {
            async_log(LOG_INFO, "PREROUTING : %pI4 -> %pI4", &iph->saddr, &iph->daddr);
        }
    }
    
    return NF_ACCEPT;
}

// Hook function for INPUT chain
unsigned int hook_input_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;

    if (indev != NULL && outdev != NULL) {
        async_log(LOG_INFO, "LOCALIN : %s -> %s", indev->name, outdev->name);
    }
    else if (indev != NULL && outdev == NULL) {
        async_log(LOG_INFO, "LOCALIN : %s ->", indev->name);
    }
    else if (indev == NULL && outdev != NULL) {
        async_log(LOG_INFO, "LOCALIN : -> %s", outdev->name);
    }
    else if (indev == NULL && outdev == NULL) {
        async_log(LOG_INFO, "LOCALIN : ->");
    }

    // Check if the incoming device is docker0
    if (indev && strcmp(indev->name, "docker0") == 0) {
        iph = ip_hdr(skb);
        
        if (iph) {
            async_log(LOG_INFO, "LOCALIN : %pI4 -> %pI4", &iph->saddr, &iph->daddr);
        }
    }

    return NF_ACCEPT;
}

// Hook function for FORWARD chain
unsigned int hook_forward_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;

    if (indev != NULL && outdev != NULL) {
        async_log(LOG_INFO, "FORWARD : [%d]%s -> [%d]%s", indev->ifindex, indev->name, outdev->ifindex,  outdev->name);
    }
    else if (indev != NULL && outdev == NULL) {
        async_log(LOG_INFO, "FORWARD : %s ->", indev->name);
    }
    else if (indev == NULL && outdev != NULL) {
        async_log(LOG_INFO, "FORWARD : -> %s", outdev->name);
    }
    else if (indev == NULL && outdev == NULL) {
        async_log(LOG_INFO, "FORWARD : ->");
    }

    // Check if the incoming device is docker0
    if (indev && strcmp(indev->name, "docker0") == 0) {
        iph = ip_hdr(skb);
        
        if (iph) {
            async_log(LOG_INFO, "FORWARD : %pI4 -> %pI4", &iph->saddr, &iph->daddr);
        }
    }

    return NF_ACCEPT;
}

// Hook function for OUTPUT chain
unsigned int hook_output_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;

    if (indev != NULL && outdev != NULL) {
        async_log(LOG_INFO, "LOCALOUT : %s -> %s", indev->name, outdev->name);
    }
    else if (indev != NULL && outdev == NULL) {
        async_log(LOG_INFO, "LOCALOUT : %s ->", indev->name);
    }
    else if (indev == NULL && outdev != NULL) {
        async_log(LOG_INFO, "LOCALOUT : -> %s", outdev->name);
    }
    else if (indev == NULL && outdev == NULL) {
        async_log(LOG_INFO, "LOCALOUT : ->");
    }

    // Check if the incoming device is docker0
    if (indev && strcmp(indev->name, "docker0") == 0) {
        iph = ip_hdr(skb);
        
        if (iph) {
            async_log(LOG_INFO, "LOCALOUT : %pI4 -> %pI4", &iph->saddr, &iph->daddr);
        }
    }

    return NF_ACCEPT;
}

// Hook function for POSTROUTING chain
unsigned int hook_postrouting_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct net_device *indev = state->in;
    struct net_device *outdev = state->out;

    if (indev != NULL && outdev != NULL) {
        async_log(LOG_INFO, "POSTROUTING : %s -> %s", indev->name, outdev->name);
    }
    else if (indev != NULL && outdev == NULL) {
        async_log(LOG_INFO, "POSTROUTING : %s ->", indev->name);
    }
    else if (indev == NULL && outdev != NULL) {
        async_log(LOG_INFO, "POSTROUTING : -> %s", outdev->name);
    }
    else if (indev == NULL && outdev == NULL) {
        async_log(LOG_INFO, "POSTROUTING : ->");
    }

    // Check if the incoming device is docker0
    if (indev && strcmp(indev->name, "docker0") == 0) {
        iph = ip_hdr(skb);
        
        if (iph) {
            async_log(LOG_INFO, "POSTROUTING : %pI4 -> %pI4", &iph->saddr, &iph->daddr);
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_prerouting = {
    .hook = hook_prerouting_func,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nfho_input = {
    .hook = hook_input_func,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nfho_forward = {
    .hook = hook_forward_func,
    .pf = PF_INET,
    .hooknum = NF_INET_FORWARD,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nfho_output = {
    .hook = hook_output_func,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nfho_postrouting = {
    .hook = hook_postrouting_func,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};


int nf_hook_init() {
    nf_register_net_hook(&init_net, &nfho_prerouting);
    nf_register_net_hook(&init_net, &nfho_input);
    nf_register_net_hook(&init_net, &nfho_forward);
    nf_register_net_hook(&init_net, &nfho_output);
    nf_register_net_hook(&init_net, &nfho_postrouting);
    return 0;
}

void nf_hook_exit() {
    nf_unregister_net_hook(&init_net, &nfho_prerouting);
    nf_unregister_net_hook(&init_net, &nfho_input);
    nf_unregister_net_hook(&init_net, &nfho_forward);
    nf_unregister_net_hook(&init_net, &nfho_output);
    nf_unregister_net_hook(&init_net, &nfho_postrouting);
}