#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "filter_rule_utils.h"
#include "conf_utils.h"
#include "netlink_msg.h"
#include "netlink_utils.h"

// 同步内核操作，等待内核返回
struct config_mutex_cond_struct {
    void *conf;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

static struct config_mutex_cond_struct config_log_get_mutex_cond = {
    .conf = NULL,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};

static struct config_mutex_cond_struct config_rule_dump_mutex_cond = {
    .conf = NULL,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};

// 消息处理器加锁
static pthread_mutex_t config_handler_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t config_handler_cond = PTHREAD_COND_INITIALIZER;

int nl_msg_config_handler(struct nl_msg_struct *msg) {
    int config_type;
    void *conf;
    int ret = 0;
    struct timespec ts;
    if (msg == NULL || msg->msg_type != NL_MSG_CONF) {
        return -1;
    }
    config_type = *(int *)NL_MSG_DATA(msg);
    pthread_mutex_lock(&config_handler_mutex);
    switch (config_type) {
        case CONF_LOG_SET:
            break;
        case CONF_LOG_GET:
            conf = (void *)NL_MSG_DATA(msg);
            if (config_log_get_mutex_cond.conf != NULL) {
                memcpy(config_log_get_mutex_cond.conf, conf, sizeof(LogConfig));
                pthread_cond_signal(&(config_log_get_mutex_cond.cond));
                // 1s超时
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += 1;
                if (pthread_cond_timedwait(&config_handler_cond, &config_handler_mutex, &ts) == ETIMEDOUT) {
                    ret = -1;
                }
            }
            break;
        case CONF_RULE_CLEAR:
            break;
        case CONF_RULE_INSERT:
            break;
        case CONF_RULE_REMOVE:
            break;
        case CONF_RULE_DUMP:
            conf = (void *)NL_MSG_DATA(msg);
            if (config_rule_dump_mutex_cond.conf != NULL) {
                memcpy(config_rule_dump_mutex_cond.conf, conf, sizeof(RuleConfig));
                pthread_cond_signal(&(config_rule_dump_mutex_cond.cond));
                // 1s超时
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += 1;
                if (pthread_cond_timedwait(&config_handler_cond, &config_handler_mutex, &ts) == ETIMEDOUT) {
                    ret = -1;
                }
            }
            break;
    }
    pthread_mutex_unlock(&config_handler_mutex);
    return ret;
}

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

    // 等待内核返回配置信息
    pthread_mutex_lock(&(config_log_get_mutex_cond.mutex));
    config_log_get_mutex_cond.conf = conf;

    nl_send_msg(msg);

    // 1s超时
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1;
    if (pthread_cond_timedwait(&(config_log_get_mutex_cond.cond), &(config_log_get_mutex_cond.mutex), &ts) == ETIMEDOUT) {
        ret = -1;
    }
    config_log_get_mutex_cond.conf = NULL;
    pthread_cond_signal(&config_handler_cond);
    pthread_mutex_unlock(&(config_log_get_mutex_cond.mutex));

    free(msg);
    return ret;
}

int config_rule_clear(int hook_chain) {
    RuleConfig conf;
    struct nl_msg_struct *msg;
    int ret;
    conf.config_type = CONF_RULE_CLEAR;
    conf.hook_chain = hook_chain;
    msg = (struct nl_msg_struct *)malloc(NL_MSG_SIZE(sizeof(RuleConfig)));
    if (msg == NULL) {
        return -1;
    }
    msg->msg_type = NL_MSG_CONF;
    msg->msg_size = NL_MSG_SIZE(sizeof(RuleConfig));
    memcpy(NL_MSG_DATA(msg), &conf, sizeof(RuleConfig));
    ret = nl_send_msg(msg);
    free(msg);
    return ret;
}

int config_rule_insert(RuleConfig *conf, int index) {
    struct nl_msg_struct *msg;
    int ret;
    if (conf == NULL) {
        return -1;
    }
    conf->config_type = CONF_RULE_INSERT;
    conf->index = index;
    msg = (struct nl_msg_struct *)malloc(NL_MSG_SIZE(sizeof(RuleConfig)));
    if (msg == NULL) {
        return -1;
    }
    msg->msg_type = NL_MSG_CONF;
    msg->msg_size = NL_MSG_SIZE(sizeof(RuleConfig));
    memcpy(NL_MSG_DATA(msg), conf, sizeof(RuleConfig));
    ret = nl_send_msg(msg);
    free(msg);
    return ret;
}

int config_rule_remove(int hook_chain, int index) {
    RuleConfig conf;
    struct nl_msg_struct *msg;
    int ret;
    conf.config_type = CONF_RULE_REMOVE;
    conf.hook_chain = hook_chain;
    conf.index = index;
    msg = (struct nl_msg_struct *)malloc(NL_MSG_SIZE(sizeof(RuleConfig)));
    if (msg == NULL) {
        return -1;
    }    config_rule_dump_mutex_cond.conf = NULL;
    msg->msg_type = NL_MSG_CONF;
    msg->msg_size = NL_MSG_SIZE(sizeof(RuleConfig));
    memcpy(NL_MSG_DATA(msg), &conf, sizeof(RuleConfig));
    ret = nl_send_msg(msg);
    free(msg);
    return ret;
}

int config_rule_dump(int hook_chain, FILE *fp, int with_index) {
    RuleConfig conf;
    struct nl_msg_struct *msg;
    int ret = 0;
    int index;
    struct timespec ts;
    char tmpfile[sizeof(conf.rule_str)];
    FILE *dump_fp;
    if (fp == NULL)  {
        return -1;
    }
    // 生成一个随机文件名用于内核传递dump信息
    clock_gettime(CLOCK_REALTIME, &ts);
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/.lite-filter-%ld-%ld", ts.tv_sec, ts.tv_nsec);
    conf.config_type = CONF_RULE_DUMP;
    conf.hook_chain = hook_chain;
    strncpy(conf.rule_str, tmpfile, sizeof(conf.rule_str));
    msg = (struct nl_msg_struct *)malloc(NL_MSG_SIZE(sizeof(RuleConfig)));
    if (msg == NULL) {
        return -1;
    }
    msg->msg_type = NL_MSG_CONF;
    msg->msg_size = NL_MSG_SIZE(sizeof(RuleConfig));
    memcpy(NL_MSG_DATA(msg), &conf, sizeof(RuleConfig));

    // 等待内核返回配置信息
    pthread_mutex_lock(&(config_rule_dump_mutex_cond.mutex));
    config_rule_dump_mutex_cond.conf = &conf;

    nl_send_msg(msg);

    // 1s超时
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1;
    if (pthread_cond_timedwait(&(config_rule_dump_mutex_cond.cond), &(config_rule_dump_mutex_cond.mutex), &ts) == ETIMEDOUT) {
        ret = -1;
    }

    config_rule_dump_mutex_cond.conf = NULL;
    pthread_cond_signal(&config_handler_cond);
    pthread_mutex_unlock(&(config_rule_dump_mutex_cond.mutex));

    if (conf.index < 0) {
        ret = -1;
    }
    dump_fp = fopen(tmpfile, "rb");
    if (dump_fp == NULL) {
        ret = -1;
    }
    while (ret != -1 && index < conf.index) {
        if (fread(&(conf.rule), sizeof(conf.rule), 1, dump_fp) != 1) {
            ret = -1;
            break;
        }
        if (rule_format(&conf, conf.rule_str, sizeof(conf.rule_str)) != 0) {
            ret = -1;
            break;
        }
        // 输出行号
        if (with_index == 1) {
            fprintf(fp, "[%d] ", index);
        }
        // 输出规则
        fprintf(fp, "%s\n", conf.rule_str);
        index++;
    }

    if (dump_fp != NULL) {
        fclose(dump_fp);
    }
    unlink(tmpfile);

    free(msg);

    return ret;
}