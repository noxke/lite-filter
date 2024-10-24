#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "netlink_utils.h"
#include "log_utils.h"
#include "module_utils.h"

static int __init mod_init(void) {
    if (log_utils_init() != 0) {
        goto _log_init;
    }
    set_log_sender((void *)log_sender);
    set_log_level(LOG_INFO);
    set_log_kprint_level(LOG_INFO);
    
    if (netlink_init() != 0) {
        goto _netlink_init;
    }
    // 所有模块正常初始化
    goto _all_init;

    netlink_exit();
_netlink_init:
    log_utils_exit();
_log_init:
    return -1;
_all_init:
    return 0;
}

static void __exit mod_exit(void) {
    netlink_exit();
    log_utils_exit();
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("noxke <zpengkee@gmail.com>");
MODULE_DESCRIPTION("A lite filter module based on netfilter");
MODULE_VERSION("1.0");