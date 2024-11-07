#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "netlink_msg.h"
#include "netlink_utils.h"
#include "filter_rule_utils.h"
#include "log_utils.h"
#include "conf_utils.h"

#define DEAULT_CONFIG_PATH "/etc/lite-filter/lite-filter.conf"
#define BUFFER_SIZE 1024
#define MAX_PATH 256


enum {
    CMD_NONE = 0,
    CMD_START = 1,
    CMD_STOP = 2,
    CMD_LOAD = 3,
    CMD_SAVE = 4,
    CMD_CLEAR = 5,
    CMD_LOG = 6,
    CMD_CLI_LS = 11,
    CMD_CLI_ADD = 12,
    CMD_CLI_DEL = 13,
};

static int cmd = 0;
static int hook_chain = 0;
static int rule_idx = 0;
static char cmd_buffer[BUFFER_SIZE];

// lite-filter配置
static struct {
    char module_file[MAX_PATH];
    int log_level;
    int log_kprint_level;
    char log_file[MAX_PATH];
    char rule_file[MAX_PATH];
} config;

void help() {
    puts("lite-filter v1.0");
    puts("");
    puts("Usage: lite-filter CMD");
    puts("Commands:");
    puts("  help\n\tshow help infomation");
    puts("  start [-c /path/to/config]\n\tinstall module use config file, default /etc/lite-filter/lite-filter.conf");
    puts("  stop\n\tremove module");
    puts("  load [-f /path/to/rule]\n\tload rules from rule file, default stdin");
    puts("  save [-f /path/to/rule]\n\tsave rules to file, default stdout");
    puts("  log\n\tshow lite-filter logs");

    puts("ls|add|del|clear");
    // ls
    puts("  ls -t PREROUTING|LOCALIN|FORWARD|LOCALOUT|POSTROUTING|NAT");
    puts("\tlist rules in chain");
    // add
    puts("  add [-idx 1] -t PREROUTING|LOCALIN|FORWARD|LOCALOUT|POSTROUTING|NAT RULE");
    puts("\tinsert rule to chain, idx=0 insert to head, idx=-1 insert to end, default 0");
    // del
    puts("  del [-idx 1] -t PREROUTING|LOCALIN|FORWARD|LOCALOUT|POSTROUTING|NAT");
    puts("\tdelete rule from chain, idx=0 delete from head, idx=-1 delete from end, default -1");
    // clear
    puts("  clear -t PREROUTING|LOCALIN|FORWARD|LOCALOUT|POSTROUTING|NAT");
    puts("\tclear rules in chain");

    puts("Rule:");
    puts("  -i [indev][:outdev]");
    puts("  -p ICMP|TCP|UDP");
    puts("  -s [10.0.0.0][/16][:1234]");
    puts("  -d [10.0.0.0][/16][:1234]");
    puts("  -r ACCEPT|DROP|SNAT|DNAT");

    puts("SNAT|DNAT:");
    puts("  -r SNAT[:10.0.0.1[:1234]]");
    puts("\tSNAT is only available in NAT, outdev is must");
    puts("  -r DNAT[:10.0.0.1[:1234]]");
    puts("\tDNAT is only available in NAT, indev is must");
    exit(0);
}

// 命令行参数解析
int arg_parser(int argc, char *argv[]) {
    if (argc < 2) {
        help();
    }
    memset(cmd_buffer, 0, sizeof(cmd_buffer));
    if (strcmp(argv[1], "help") == 0) {
        help();
    }
    else if (strcmp(argv[1], "start") == 0) {
        cmd = CMD_START;
        if (argc >= 4 && strcmp(argv[2], "-c") == 0) {
            strncpy(cmd_buffer, argv[3], sizeof(cmd_buffer));
        }
        else {
            strncpy(cmd_buffer, DEAULT_CONFIG_PATH, sizeof(cmd_buffer));
        }
    }
    else if (strcmp(argv[1], "stop") == 0) {
        cmd = CMD_STOP;
        if (argc >= 4 && strcmp(argv[2], "-c") == 0) {
            strncpy(cmd_buffer, argv[3], sizeof(cmd_buffer));
        }
        else {
            strncpy(cmd_buffer, DEAULT_CONFIG_PATH, sizeof(cmd_buffer));
        }
    }
    else if (strcmp(argv[1], "load") == 0) {
        cmd = CMD_LOAD;
        if (argc >= 4 && strcmp(argv[2], "-f") == 0) {
            strncpy(cmd_buffer, argv[3], sizeof(cmd_buffer));
        }
    }
    else if (strcmp(argv[1], "save") == 0) {
        cmd = CMD_SAVE;
        if (argc >= 4 && strcmp(argv[2], "-f") == 0) {
            strncpy(cmd_buffer, argv[3], sizeof(cmd_buffer));
        }
    }
    else if (strcmp(argv[1], "log") == 0) {
        cmd = CMD_LOG;
    }
    else if (strcmp(argv[1], "ls") == 0) {
        cmd = CMD_CLI_LS;
        char *token = argv[3];
        if (argc < 4 || strcmp(argv[2], "-t") != 0) {
            return -1;
        }
        if (strcmp(token, "PREROUTING") == 0) {
            hook_chain = NF_HOOK_PREROUTING;
        }
        else if (strcmp(token, "LOCALIN") == 0) {
            hook_chain = NF_HOOK_LOCALIN;
        }
        else if (strcmp(token, "FORWARD") == 0) {
            hook_chain = NF_HOOK_FORWARD;
        }
        else if (strcmp(token, "LOCALOUT") == 0) {
            hook_chain = NF_HOOK_LOCALOUT;
        }
        else if (strcmp(token, "POSTROUTING") == 0) {
            hook_chain = NF_HOOK_POSTROUTING;
        }
        else if (strcmp(token, "NAT") == 0) {
            hook_chain = NF_HOOK_NAT;
        }
        else {
            return -1;
        }
    }
    else if (strcmp(argv[1], "add") == 0) {
        cmd = CMD_CLI_ADD;
        int argi;
        char *token = argv[3];
        if (argc >= 4 && strcmp(argv[2], "-idx") == 0) {
            if (sscanf(argv[3], "%d", &rule_idx) != 1) {
                return -1;
            }
            if (argc < 6 || strcmp(argv[4], "-t") != 0) {
                return -1;
            }
            token = argv[5];
            argi = 4;
        }
        else if (argc < 4 || strcmp(argv[2], "-t") != 0) {
            return -1;
        }
        else {
            rule_idx = 0;
            argi = 2;
        }
        if (strcmp(token, "PREROUTING") == 0) {
            hook_chain = NF_HOOK_PREROUTING;
        }
        else if (strcmp(token, "LOCALIN") == 0) {
            hook_chain = NF_HOOK_LOCALIN;
        }
        else if (strcmp(token, "FORWARD") == 0) {
            hook_chain = NF_HOOK_FORWARD;
        }
        else if (strcmp(token, "LOCALOUT") == 0) {
            hook_chain = NF_HOOK_LOCALOUT;
        }
        else if (strcmp(token, "POSTROUTING") == 0) {
            hook_chain = NF_HOOK_POSTROUTING;
        }
        else if (strcmp(token, "NAT") == 0) {
            hook_chain = NF_HOOK_NAT;
        }
        else {
            return -1;
        }
        char *buf_p = cmd_buffer;
        for (int i = argi; i < argc; i++) {
            strncpy(buf_p, argv[i], sizeof(cmd_buffer)-(cmd_buffer-buf_p));
            buf_p += strlen(buf_p);
            *buf_p = ' ';
            buf_p++;
        }
    }
    else if (strcmp(argv[1], "del") == 0) {
        cmd = CMD_CLI_DEL;
        char *token = argv[3];
        if (argc >= 4 && strcmp(argv[2], "-idx") == 0) {
            if (sscanf(argv[3], "%d", &rule_idx) != 1) {
                return -1;
            }
            if (argc < 6 || strcmp(argv[4], "-t") != 0) {
                return -1;
            }
            token = argv[5];
        }
        else if (argc < 4 || strcmp(argv[2], "-t") != 0) {
            return -1;
        }
        else {
            rule_idx = 0;
        }
        if (strcmp(token, "PREROUTING") == 0) {
            hook_chain = NF_HOOK_PREROUTING;
        }
        else if (strcmp(token, "LOCALIN") == 0) {
            hook_chain = NF_HOOK_LOCALIN;
        }
        else if (strcmp(token, "FORWARD") == 0) {
            hook_chain = NF_HOOK_FORWARD;
        }
        else if (strcmp(token, "LOCALOUT") == 0) {
            hook_chain = NF_HOOK_LOCALOUT;
        }
        else if (strcmp(token, "POSTROUTING") == 0) {
            hook_chain = NF_HOOK_POSTROUTING;
        }
        else if (strcmp(token, "NAT") == 0) {
            hook_chain = NF_HOOK_NAT;
        }
        else {
            return -1;
        }
    }
    else if (strcmp(argv[1], "clear") == 0) {
        cmd = CMD_CLEAR;
        char *token = argv[3];
        if (argc < 4 || strcmp(argv[2], "-t") != 0) {
            return -1;
        }
        if (strcmp(token, "PREROUTING") == 0) {
            hook_chain = NF_HOOK_PREROUTING;
        }
        else if (strcmp(token, "LOCALIN") == 0) {
            hook_chain = NF_HOOK_LOCALIN;
        }
        else if (strcmp(token, "FORWARD") == 0) {
            hook_chain = NF_HOOK_FORWARD;
        }
        else if (strcmp(token, "LOCALOUT") == 0) {
            hook_chain = NF_HOOK_LOCALOUT;
        }
        else if (strcmp(token, "POSTROUTING") == 0) {
            hook_chain = NF_HOOK_POSTROUTING;
        }
        else if (strcmp(token, "NAT") == 0) {
            hook_chain = NF_HOOK_NAT;
        }
        else {
            return -1;
        }
    }
    else {
        return -1;
    }
    return 0;
}

// 配置文件解析
int conf_parser(const char *conf_file) {
    FILE *fp;
    char line_buf[BUFFER_SIZE];
    if (conf_file == NULL) {
        return -1;
    }
    memset(&config, 0, sizeof(config));
    fp = fopen(conf_file, "rt");
    if (fp == NULL) {
        return -1;
    }
    while (fgets(line_buf, sizeof(line_buf), fp) != NULL) {
        char *key_p = line_buf;
        char *value_p;
        // 去除前缀空白字符
        while ((strlen(key_p) > 0) && (*key_p == ' ' || *key_p == '\t')) {
            key_p++;
        }
        // 去除注释行
        if (strlen(key_p) == 0 || *key_p == '#') {
            continue;
        }
        value_p = key_p;
        // 找到key value分隔符号
        while (strlen(value_p) > 0 && *value_p != ' ' && *value_p != '=') {
            value_p++;
        }
        while (strlen(value_p) > 0 && (*value_p == ' ' || *value_p == '=')) {
            *value_p = '\0';
            value_p++;
        }
        // 去除末尾空白后缀
        char *cp = value_p;
        while (strlen(cp) != 0 && *cp != ' ' && *cp != '\n') {
            cp++;
        }
        if (strlen(cp) != 0) {
            *cp = '\0';
        }

        if (strlen(key_p) == 0 || strlen(value_p) == 0) {
            continue;
        }

        if (strcmp(key_p, "module") == 0) {
            strncpy(config.module_file, value_p, sizeof(config.module_file));
        }
        else if (strcmp(key_p, "log_level") == 0) {
            if (strcmp(value_p, "LOG_NONE") == 0) {
                config.log_level = LOG_NONE;
            }
            else if (strcmp(value_p, "LOG_INFO") == 0) {
                config.log_level = LOG_INFO;
            }
            else if (strcmp(value_p, "LOG_WARNING") == 0) {
                config.log_level = LOG_WARNING;
            }
            else if (strcmp(value_p, "LOG_ERROR") == 0) {
                config.log_level = LOG_ERROR;
            }
        }
        else if (strcmp(key_p, "log_kprint_level") == 0) {
            if (strcmp(value_p, "LOG_NONE") == 0) {
                config.log_kprint_level = LOG_NONE;
            }
            else if (strcmp(value_p, "LOG_INFO") == 0) {
                config.log_kprint_level = LOG_INFO;
            }
            else if (strcmp(value_p, "LOG_WARNING") == 0) {
                config.log_kprint_level = LOG_WARNING;
            }
            else if (strcmp(value_p, "LOG_ERROR") == 0) {
                config.log_kprint_level = LOG_ERROR;
            }
        }
        else if (strcmp(key_p, "log_file") == 0) {
            strncpy(config.log_file, value_p, sizeof(config.log_file));
        }
        else if (strcmp(key_p, "rule") == 0) {
            strncpy(config.rule_file, value_p, sizeof(config.rule_file));
        }
    }
    fclose(fp);
    if (access(config.module_file, R_OK) != 0) {
        return -1;
    }
    return 0;
}

int cmd_load() {
    RuleConfig conf;
    char line_buf[BUFFER_SIZE];
    FILE *fp;
    int ret = 0;
    if (strlen(cmd_buffer) == 0) {
        fp = stdin;
    }
    else {
        fp = fopen(cmd_buffer, "rt");
    }
    if (fp == NULL) {
        printf("Invalid rule file: %s\n", cmd_buffer);
        return -1;
    }
    while (fgets(line_buf, sizeof(line_buf), fp) != NULL) {
        memset(&conf, 0, sizeof(conf));
        if (rule_parser(line_buf, &conf) != 0 || rule_format(&conf, conf.rule_str, sizeof(conf.rule_str)) != 0) {
            ret = -1;
            break;
        }
        // 默认往末尾插入
        if (config_rule_insert(&conf, -1) != 0) {
            ret = -1;
            break;
        }
    }
    if (fp != stdin) {
        fclose(fp);
    }
    return ret;
}

int cmd_save() {
    FILE *fp;
    int ret = 0;
    if (strlen(cmd_buffer) == 0) {
        fp = stdout;
    }
    else {
        fp = fopen(cmd_buffer, "wt");
    }
    if (fp == NULL) {
        printf("Invalid rule file: %s\n", cmd_buffer);
        return -1;
    }

    for (int i = NF_HOOK_NONE+1; i < NF_HOOK_MAX; i++) {
        if (config_rule_dump(i, fp) != 0) {
            ret = -1;
            break;
        }
    }
    
    if (fp != stdout) {
        fclose(fp);
    }
    return ret;
}

int cmd_start() {
    LogConfig conf;
    memset(&conf, 0, sizeof(conf));
    conf.config_type = CONF_LOG_SET;
    conf.log_level = config.log_level;
    conf.log_kprint_level = config.log_kprint_level;
    strncpy(conf.log_file, config.log_file, sizeof(conf.log_file));
    if (config_log_set(&conf) != 0) {
        return -1;
    }
    if (strlen(config.rule_file) != 0) {
        strncpy(cmd_buffer, config.rule_file, sizeof(cmd_buffer));
        return cmd_load();
    }
    return 0;
}

int cmd_log() {
    LogConfig conf;
    FILE *fp;
    char line_buf[BUFFER_SIZE];
    memset(&conf, 0, sizeof(conf));
    conf.config_type = CONF_LOG_GET;
    if (config_log_get(&conf) != 0) {
        return -1;
    }
    fp = fopen(conf.log_file, "rt");
    if (fp == NULL) {
        return -1;
    }
    while (fgets(line_buf, sizeof(line_buf), fp) != NULL) {
        printf("%s", line_buf);
    }
    fclose(fp);
    return 0;
}

int cmd_ls() {
    return config_rule_dump(hook_chain, stdout);
}

int cmd_add() {
    RuleConfig conf;
    if (rule_parser(cmd_buffer, &conf) != 0) {
        return -1;
    }
    return config_rule_insert(&conf, rule_idx);
}

int cmd_del() {
    return config_rule_remove(hook_chain, rule_idx);
}

int cmd_clear() {
    return config_rule_clear(hook_chain);
}

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
    int ret = 0;
    if (cmd == CMD_START) {
        if (conf_parser(cmd_buffer) != 0) {
            printf("Invalid config file: %s\n", cmd_buffer);
            return -1;
        }
        snprintf(cmd_buffer, sizeof(cmd_buffer), "insmod %s", config.module_file);
        system(cmd_buffer);
    }
    if (service_init() != 0) {
        printf("Connect lite_filter module failed\n");
        return -1;
    }

    switch (cmd) {
        case CMD_START:
            ret = cmd_start();
            break;
        case CMD_STOP:
            service_exit();
            system("rmmod lite_filter");
            return 0;
            break;
        case CMD_LOAD:
            ret = cmd_load();
            break;
        case CMD_SAVE:
            ret = cmd_save();
            break;
        case CMD_LOG:
            ret = cmd_log();
            break;
        case CMD_CLI_LS:
            ret = cmd_ls();
            break;
        case CMD_CLI_ADD:
            ret = cmd_add();
            break;
        case CMD_CLI_DEL:
            ret = cmd_del();
            break;
        case CMD_CLEAR:
            ret = cmd_clear();
            break;
        default:
            ret = -1;
    }

    service_exit();
    return ret;
}

int main(int argc, char *argv[], char *envp[]) {
    if (geteuid() != 0) {
        puts("lite-filter: Operation not permitted");
        return -1;
    }
    if (arg_parser(argc, argv) != 0) {
        puts("lite-filter: Invalid usage");
        return -1;
    }
    if (service_main() != 0) {
        puts("lite-filter: Internal Error");
        return -1;
    }
    return 0;
}