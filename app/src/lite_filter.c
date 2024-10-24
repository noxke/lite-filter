#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "netlink_msg.h"
#include "netlink_utils.h"
#include "log_utils.h"

int service_init() {
    // 初始化netlink
    if (netlink_init() != 0) {
        goto _service_netlink_init;
    }

    // 设置日志消息处理器
    netlink_set_msg_handler(NL_MSG_LOG, (void *)log_msg_handler);

    goto _service_all_init;

_service_netlink_init:
    return -1;
_service_all_init:
    return 0;
}

void service_exit() {
    netlink_exit();
}

int service_main() {
    if (service_init() != 0) {
        return -1;
    }

    struct nl_msg_struct *rep_msg;
    char s[] = "11111111111111111111111111111111";
    int s_size;
    s_size = strlen(s);
    rep_msg = malloc(NL_MSG_SIZE(s_size));
    rep_msg->msg_type = NL_MSG_RAW;
    rep_msg->msg_size = NL_MSG_SIZE(s_size);
    if (rep_msg == NULL) {
        return -1;
    }
    memcpy(NL_MSG_DATA(rep_msg), s, s_size);
    nl_send_msg(rep_msg);
    free(rep_msg);
    sleep(3);

    service_exit();
    return 0;
}

int main(int argc, char *argv[], char *envp[]) {
    service_main();
    return 0;
}