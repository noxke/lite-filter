#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "netlink_msg.h"
#include "netlink_utils.h"
#include "log_utils.h"

#include "module_utils.h"

int log_sender(int log_level, char *s) {
    struct nl_msg_struct *msg;
    unsigned int msg_size, s_len;
    int ret;
    s_len = strlen(s) + 1;
    msg_size = s_len+sizeof(int);

    msg = (struct nl_msg_struct *)kmalloc(NL_MSG_SIZE(msg_size), GFP_KERNEL);
    if (msg == NULL)
    {
        return -1;
    }
    msg->msg_type = NL_MSG_LOG;
    msg->msg_size = NL_MSG_SIZE(msg_size);
    *(int *)NL_MSG_DATA(msg) = log_level;
    memcpy((char *)NL_MSG_DATA(msg)+sizeof(int), s, s_len);
    ret = nl_send_msg(msg);
    kfree(msg);
    return ret;
}