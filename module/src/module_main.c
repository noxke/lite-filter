#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "netlink_utils.h"
#include "log_utils.h"
#include "module_utils.h"
#include "netfilter_hook.h"

static int __init mod_init(void) {
    if (log_utils_init() != 0) {
        goto _log_init;
    }
    
    if (netlink_init() != 0) {
        goto _netlink_init;
    }

    if (nf_hook_init() != 0) {
        goto _nf_hook_init;
    }

    netlink_set_msg_handler(NL_MSG_CONF, (void *)nl_msg_config_handler);

    // 所有模块正常初始化
    goto _all_init;

    nf_hook_exit();
_nf_hook_init:
    netlink_exit();
_netlink_init:
    log_utils_exit();
_log_init:
    return -1;
_all_init:
    return 0;
}

static void __exit mod_exit(void) {
    nf_hook_exit();
    netlink_exit();
    log_utils_exit();
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("noxke <zpengkee@gmail.com>");
MODULE_DESCRIPTION("A lite filter module based on netfilter");
MODULE_VERSION("1.0");