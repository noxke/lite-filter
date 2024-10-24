#ifndef __NETLINK_UTILS_H__ //__NETLINK_UTILS_H__
#define __NETLINK_UTILS_H__
// netlink接口
#include "netlink_msg.h"

#define NETLINK_USER 19

extern int nl_send_msg(struct nl_msg_struct *msg);

extern void nl_send_ack(void);

extern void netlink_set_msg_handler(NL_MSG_TYPE msg_type, void *handler);
extern int netlink_init(void);
extern void netlink_exit(void);

#endif // __NETLINK_UTILS_H__