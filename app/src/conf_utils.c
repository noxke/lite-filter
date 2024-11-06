#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "conf_utils.h"
#include "netlink_msg.h"
#include "netlink_utils.h"

LogConfig *config_log_get_conf_p = NULL;
pthread_mutex_t config_log_get_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t config_log_get_cond = PTHREAD_COND_INITIALIZER;

int config_log_set(LogConfig *conf) {
    struct nl_msg_struct *msg;
    int ret;
    if (conf == NULL) {
        return -1;
    }
    conf->config_type = CONF_LOG_SET;
    msg = (struct nl_msg_struct *)malloc(NL_MSG_SIZE(sizeof(LogConfig)));
    if (msg == NULL) {
        return -1;
    }
    msg->msg_type = NL_MSG_CONF;
    msg->msg_size = NL_MSG_SIZE(sizeof(LogConfig));
    memcpy(NL_MSG_DATA(msg), conf, sizeof(LogConfig));
    ret = nl_send_msg(msg);
    free(msg);
    return ret;
}


int config_log_get(LogConfig *conf) {
    struct nl_msg_struct *msg;
    LogConfig *conf_send;
    int ret = 0;
    struct timespec ts;
    if (conf == NULL) {
        return -1;
    }
    msg = (struct nl_msg_struct *)malloc(NL_MSG_SIZE(sizeof(LogConfig)));
    if (msg == NULL) {
        return -1;
    }
    msg->msg_type = NL_MSG_CONF;
    msg->msg_size = NL_MSG_SIZE(sizeof(LogConfig));
    conf_send = (LogConfig *)NL_MSG_DATA(msg);
    conf_send->config_type = CONF_LOG_GET;
    ret = nl_send_msg(msg);
    free(msg);
    if (ret == -1) {
        return ret;
    }

    // 等待内核返回配置信息
    pthread_mutex_lock(&config_log_get_mutex);
    config_log_get_conf_p = conf;
    // 1s超时
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1;
    if (pthread_cond_timedwait(&config_log_get_cond, &config_log_get_mutex, &ts) == ETIMEDOUT) {
        ret = -1;
    }
    config_log_get_conf_p = NULL;
    pthread_mutex_unlock(&config_log_get_mutex);

    return ret;
}

int nl_msg_config_handler(struct nl_msg_struct *msg) {
    int config_type;
    if (msg == NULL || msg->msg_type != NL_MSG_CONF) {
        return -1;
    }
    config_type = *(int *)NL_MSG_DATA(msg);
    switch (config_type) {
        case CONF_LOG_SET:
            break;
        case CONF_LOG_GET:
            LogConfig *conf = (LogConfig *)NL_MSG_DATA(msg);
            if (config_log_get_conf_p != NULL) {
                memcpy(config_log_get_conf_p, conf, sizeof(LogConfig));
                pthread_cond_signal(&config_log_get_cond);
            }
            break;
        case CONF_RULE_CLEAR:
            break;
        case CONF_RULE_INSERT:
            break;
        case CONF_RULE_REMOVE:
            break;
        case CONF_RULE_DUMP:
            break;
    }
    return 0;
}