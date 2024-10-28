#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "netlink_msg.h"
#include "netlink_utils.h"
#include "filter_rule_utils.h"
#include "log_utils.h"

int service_init() {
    // 初始化netlink
    if (netlink_init() != 0) {
        goto _service_netlink_init;
    }

    // 设置过滤器配置
    netlink_set_msg_handler(NL_MSG_CONF, (void *)nl_msg_config_handler);

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

    service_exit();
    return 0;
}

int main(int argc, char *argv[], char *envp[]) {
    service_main();
    return 0;
}