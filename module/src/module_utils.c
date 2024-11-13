#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "netlink_msg.h"
#include "netlink_utils.h"
#include "log_utils.h"
#include "filter_rule_utils.h"
#include "filter_conn_utils.h"
#include "filter_nat_utils.h"

#include "module_utils.h"

int nl_msg_config_handler(struct nl_msg_struct *msg) {
    void *conf = (void *)NL_MSG_DATA(msg);
    int config_type = *(int *)conf;
    switch (config_type) {
        case CONF_LOG_SET:
        case CONF_LOG_GET:
            log_config((LogConfig *)conf);
            break;
        case CONF_RULE_CLEAR:
        case CONF_RULE_INSERT:
        case CONF_RULE_REMOVE:
        case CONF_RULE_DUMP:
            filter_rule_config((RuleConfig *)conf);
            break;
        case CONF_CONN_CLEAR:
        case CONF_CONN_DUMP:
            filter_conn_config((ConnConfig *)conf);
            break;
        case CONF_NAT_CLEAR:
        case CONF_NAT_DUMP:
            filter_nat_config((NatConfig *)conf);
            break;
    }
    return 0;
}