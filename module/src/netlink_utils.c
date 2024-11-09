#include <linux/kernel.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/cred.h>

#include "log_utils.h"
#include "netlink_msg.h"
#include "netlink_utils.h"

struct sock *nl_sk = NULL;
static pid_t app_pid = 0;
static int (*nl_msg_handlers[MAX_NL_MSG_TYPE])(struct nl_msg_struct *msg);

static int nl_msg_handler_default(struct nl_msg_struct *msg) {
    return 0;
}

int nl_send_msg(struct nl_msg_struct *msg) {
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int msg_size;
    if (msg == NULL || app_pid == 0) {
        return -1;
    }

    msg_size = msg->msg_size;

    skb_out = nlmsg_new(msg_size, 0);

    if (!skb_out) {
        return -1;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(nlmsg_data(nlh), (char *)msg, msg_size);

    return nlmsg_unicast(nl_sk, skb_out, app_pid);
}

void nl_send_ack() {
    struct nl_msg_struct msg;
    msg.msg_size = NL_MSG_SIZE(0);
    msg.msg_type = NL_MSG_ACK;
    nl_send_msg(&msg);
}

void nl_recv_msg(struct sk_buff *skb) {
    // kuid_t uid, euid;
    struct nlmsghdr *nlh;
    struct nl_msg_struct *msg;
    unsigned int msg_size;

    nlh = nlmsg_hdr(skb);

    // 检查权限，仅允许root用户
    if (uid_eq(__task_cred(current)->euid, GLOBAL_ROOT_UID) == 0) {
        async_log(LOG_WARNING, "[MODULE] Non-root user, operation not permitte.");
        return;
    }

    // 检查pid是否真实
    if (nlh->nlmsg_pid != task_tgid_vnr(current)) {
        async_log(LOG_WARNING, "[MODULE] PID error, app pid: %d, msg pid: %d", task_tgid_vnr(current), nlh->nlmsg_pid);
        return;
    }
    
    msg = (struct nl_msg_struct *)NLMSG_DATA(nlh);
    msg_size = nlh->nlmsg_len - NLMSG_HDRLEN;
    // nlh中的size存在对其，大小不一定与真实消息相等
    if (msg_size < msg->msg_size || msg_size > NL_MAX_MSG_SIZE) {
        return;
    }
    if (msg->msg_type >= NL_MSG_RAW && msg->msg_type <= NL_MSG_MAX) {
        app_pid = nlh->nlmsg_pid;
        switch(msg->msg_type) {
            case NL_MSG_ALIVE:
                nl_send_ack();
                break;
            default:
                if (app_pid == nlh->nlmsg_pid) {
                    nl_msg_handlers[msg->msg_type](msg);
                }
                break;
        }
    }
}

void netlink_set_msg_handler(NL_MSG_TYPE msg_type, void *handler) {
    if (msg_type >= NL_MSG_RAW && msg_type <= NL_MSG_MAX) {
        nl_msg_handlers[msg_type] = handler;
    }
}

int netlink_init(void) {
    int i;
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (nl_sk == NULL) {
        async_log(LOG_ERROR, "[MODULE] Error creating socket.");
        return -10;
    }
    for (i = 0; i < MAX_NL_MSG_TYPE; i++) {
        nl_msg_handlers[i] = nl_msg_handler_default;
    }
    async_log(LOG_WARNING, "[MODULE] Create netlink socket.");
    return 0;
}

void netlink_exit(void) {
    if (nl_sk != NULL) {
        netlink_kernel_release(nl_sk);
        async_log(LOG_WARNING, "[MODULE] Close, netlink socket.");
    }
}
