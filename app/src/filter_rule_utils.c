#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "log_utils.h"
#include "filter_rule_utils.h"

int get_interface_index(const char *if_name) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        // perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        // perror("ioctl");
        close(sock);
        return -1;
    }

    close(sock);
    return ifr.ifr_ifindex;
}


int get_interface_name(int if_index, char *if_name, int name_size) {
    if (if_name == NULL || name_size < 0) {
        return -1;
    }
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        // perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_ifindex = if_index;

    if (ioctl(sock, SIOCGIFNAME, &ifr) == -1) {
        // perror("ioctl");
        close(sock);
        return -1;
    }

    strncpy(if_name, ifr.ifr_name, name_size - 1);

    close(sock);
    return 0;
}

int get_interface_address(int ifindex, struct in_addr *addr) {
    int sockfd;
    struct ifreq ifr;

    if (addr == NULL) {
        return -1;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    if_indextoname(ifindex, ifr.ifr_name);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        close(sockfd);
        return -1;
    }

    close(sockfd);

    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->s_addr = ipaddr->sin_addr.s_addr;

    return 0;
}

int rule_parser(const char *rule_str, RuleConfig *rule) {
    int ret  = 0;
    int only_chain = 1;
    char *token;
    char *tmp_token;
    char str[MAX_RULE_STR_SIZE];
    char tmp_str[MAX_RULE_STR_SIZE];
    if (rule == NULL || rule_str == NULL || strlen(rule_str) <= 0) {
        return -1;
    }
    memset(rule, 0, sizeof(RuleConfig));
    strncpy(str, rule_str, sizeof(str));
    // strip
    token = str + strlen(str) - 1;
    while ((token >= str) && (*token == '\n' || *token == ' ' || *token == '\t')) {
        *token = '\0';
        token--;
    }
    token = strtok(str, " ");
    do {
        if (token[0] == '[' || strcmp(token, "-t") == 0) {
            if (token[0] == '[' && token[strlen(token)-1] == ']') {
                token++;
                token[strlen(token)-1] = '\0';
            }
            else {
                token = strtok(NULL, " ");
            }
            if (strcmp(token, "PREROUTING") == 0) {
                rule->hook_chain = NF_HOOK_PREROUTING;
            }
            else if (strcmp(token, "LOCALIN") == 0) {
                rule->hook_chain = NF_HOOK_LOCALIN;
            }
            else if (strcmp(token, "FORWARD") == 0) {
                rule->hook_chain = NF_HOOK_FORWARD;
            }
            else if (strcmp(token, "LOCALOUT") == 0) {
                rule->hook_chain = NF_HOOK_LOCALOUT;
            }
            else if (strcmp(token, "POSTROUTING") == 0) {
                rule->hook_chain = NF_HOOK_POSTROUTING;
            }
            else if (strcmp(token, "NAT") == 0) {
                rule->hook_chain = NF_HOOK_NAT;
            } else {
                ret = -1;
                break;
            }
        }
        else {
            only_chain = 0;
        }
        if (strcmp(token, "-i") == 0) {
            token = strtok(NULL, " ");
            if (token == NULL) {
                ret = -1;
                break;
            }
            strncpy(tmp_str, token, sizeof(tmp_str));
            tmp_token = tmp_str;
            while (tmp_token[0] != ':' && tmp_token[0] != '\0') {
                tmp_token++;
            }
            if (tmp_token[0] == ':') {
                tmp_token[0] = '\0';
                tmp_token++;
            }
            int indev = get_interface_index(tmp_str);
            int outdev = get_interface_index(tmp_token);
            if (indev != -1) {
                rule->rule.indev = indev;
                rule->rule.match_flags |= FILTER_MATCH_INDEV;
            }
            if (outdev != -1) {
                rule->rule.outdev = outdev;
                rule->rule.match_flags |= FILTER_MATCH_OUTDEV;
            }
        }
        else if (strcmp(token, "-p") == 0) {
            token = strtok(NULL, " ");
            if (token == NULL) {
                ret = -1;
                break;
            }
            if (strcmp(token, "ICMP") == 0) {
                rule->rule.protocol = IPPROTO_ICMP;
                rule->rule.match_flags |= FILTER_MATCH_PROTO;
            }
            else if (strcmp(token, "UDP") == 0) {
                rule->rule.protocol = IPPROTO_UDP;
                rule->rule.match_flags |= FILTER_MATCH_PROTO;
            }
            else if (strcmp(token, "TCP") == 0) {
                rule->rule.protocol = IPPROTO_TCP;
                rule->rule.match_flags |= FILTER_MATCH_PROTO;
            }
            else {
                ret = -1;
                break;
            }
        }
        else if (strcmp(token, "-s") == 0) {
            token = strtok(NULL, " ");
            if (token == NULL) {
                ret = -1;
                break;
            }
            strncpy(tmp_str, token, sizeof(tmp_str));
            // 匹配端口
            tmp_token = tmp_str;
            while (tmp_token[0] != ':' && tmp_token[0] != '\0') {
                tmp_token++;
            }
            if (tmp_token[0] == ':') {
                tmp_token[0] = '\0';
                tmp_token++;
            }
            unsigned short port = 0;
            sscanf(tmp_token, "%hu", &port);
            if (port != 0) {
                rule->rule.sport = htons(port);
                rule->rule.match_flags |= FILTER_MATCH_SPORT;
            }
            // 匹配前缀
            tmp_token = tmp_str;
            while (tmp_token[0] != '/' && tmp_token[0] != '\0') {
                tmp_token++;
            }
            if (tmp_token[0] == '/') {
                tmp_token[0] = '\0';
                tmp_token++;
            }
            unsigned char prefix = 32;
            sscanf(tmp_token, "%hhu", &prefix);
            if (prefix > 32) {
                ret = -1;
                break;
            }
            rule->rule.sprefixlen = prefix;
            struct in_addr addr;
            addr.s_addr = 0;
            if (strlen(tmp_str) != 0 && inet_pton(AF_INET, tmp_str, &addr) != 1) {
                ret = -1;
                break;
            }
            rule->rule.saddr = addr.s_addr;
            rule->rule.match_flags |= FILTER_MATCH_SADDR;
        }
        else if (strcmp(token, "-d") == 0) {
            token = strtok(NULL, " ");
            if (token == NULL) {
                ret = -1;
                break;
            }
            strncpy(tmp_str, token, sizeof(tmp_str));
            // 匹配端口
            tmp_token = tmp_str;
            while (tmp_token[0] != ':' && tmp_token[0] != '\0') {
                tmp_token++;
            }
            if (tmp_token[0] == ':') {
                tmp_token[0] = '\0';
                tmp_token++;
            }
            unsigned short port = 0;
            sscanf(tmp_token, "%hu", &port);
            if (port != 0) {
                rule->rule.dport = htons(port);
                rule->rule.match_flags |= FILTER_MATCH_DPORT;
            }
            // 匹配前缀
            tmp_token = tmp_str;
            while (tmp_token[0] != '/' && tmp_token[0] != '\0') {
                tmp_token++;
            }
            if (tmp_token[0] == '/') {
                tmp_token[0] = '\0';
                tmp_token++;
            }
            unsigned char prefix = 32;
            sscanf(tmp_token, "%hhu", &prefix);
            if (prefix > 32) {
                ret = -1;
                break;
            }
            rule->rule.dprefixlen = prefix;
            struct in_addr addr;
            addr.s_addr = 0;
            if (strlen(tmp_str) != 0 && inet_pton(AF_INET, tmp_str, &addr) != 1) {
                ret = -1;
                break;
            }
            rule->rule.daddr = addr.s_addr;
            rule->rule.match_flags |= FILTER_MATCH_DADDR;
        }
        else if (strcmp(token, "-r") == 0) {
            token = strtok(NULL, " ");
            if (token == NULL) {
                ret = -1;
                break;
            }
            strncpy(tmp_str, token, sizeof(tmp_str));
            // 匹配动作
            tmp_token = tmp_str;
            while (tmp_token[0] != ':' && tmp_token[0] != '\0') {
                tmp_token++;
            }
            if (tmp_token[0] == ':') {
                tmp_token[0] = '\0';
                tmp_token++;
            }
            if (strcmp(tmp_str, "ACCEPT") == 0) {
                rule->rule.rule_type = FILTER_ACCEPT;
            }
            else if (strcmp(tmp_str, "DROP") == 0) {
                rule->rule.rule_type = FILTER_DROP;
            }
            else if (strcmp(tmp_str, "SNAT") == 0) {
                rule->rule.rule_type = FILTER_SNAT;
                char *tmp = tmp_token;
                tmp_token;
                while (tmp_token[0] != ':' && tmp_token[0] != '\0') {
                    tmp_token++;
                }
                if (tmp_token[0] == ':') {
                    tmp_token[0] = '\0';
                    tmp_token++;
                }
                struct in_addr addr;
                if (strlen(tmp) != 0) {
                    if (inet_pton(AF_INET, tmp, &addr) != 1) {
                        ret = -1;
                        break;
                    }
                }
                else {
                    if (get_interface_address(rule->rule.outdev, &addr) != 0) {
                        ret = -1;
                        break;
                    }
                }
                rule->rule.nataddr = addr.s_addr;
                unsigned short port = 0;
                sscanf(tmp_token, "%hu", &port);
                if (port != 0) {
                    rule->rule.natport = htons(port);
                }
            }
            else if (strcmp(tmp_str, "DNAT") == 0) {
                rule->rule.rule_type = FILTER_DNAT;
                char *tmp = tmp_token;
                tmp_token;
                while (tmp_token[0] != ':' && tmp_token[0] != '\0') {
                    tmp_token++;
                }
                if (tmp_token[0] == ':') {
                    tmp_token[0] = '\0';
                    tmp_token++;
                }
                struct in_addr addr;
                if (strlen(tmp) != 0) {
                    if (inet_pton(AF_INET, tmp, &addr) != 1) {
                        ret = -1;
                        break;
                    }
                }
                else {
                    if (get_interface_address(rule->rule.indev, &addr) != 0) {
                        ret = -1;
                        break;
                    }
                }
                rule->rule.nataddr = addr.s_addr;
                unsigned short port = 0;
                sscanf(tmp_token, "%hu", &port);
                if (port != 0) {
                    rule->rule.natport = htons(port);
                }
            }
        }
    } while ((token = strtok(NULL, " ")) != NULL);
    // 检查规则是否合理
    // ICMP不需要端口
    if ((rule->rule.match_flags & FILTER_MATCH_PROTO) != 0) {
        if (rule->rule.protocol == IPPROTO_ICMP
        && (((rule->rule.match_flags & FILTER_MATCH_SPORT) != 0) 
        || ((rule->rule.match_flags & FILTER_MATCH_DPORT) != 0))) {
            ret = -1;
        }
    }
    // SNAT
    if (rule->rule.rule_type == FILTER_SNAT) {
        // NAT链
        if (rule->hook_chain != NF_HOOK_NAT) {
            ret = -1;
        }
        // 需要outdev
        if((rule->rule.match_flags & FILTER_MATCH_OUTDEV) == 0) {
            ret = -1;
        }
    }
    // DNAT
    if (rule->rule.rule_type == FILTER_DNAT) {
        // NAT链
        if (rule->hook_chain != NF_HOOK_NAT) {
            ret = -1;
        }
        // 需要indev
        if ((rule->rule.match_flags & FILTER_MATCH_INDEV) == 0) {
            ret = -1;
        }
    }
    // 规则类型
    if ((only_chain == 0) && (rule->rule.rule_type <= FILTER_NONE || rule->rule.rule_type >=FILTER_MAX)) {
        ret = -1;
    }
    if (ret != 0) {
        lf_log(LOG_ERROR, "invalid rule: %s", rule_str);
    }
    return ret;
}

int rule_format(RuleConfig *rule, char *buf, int buf_size) {
    char *buf_p;
    struct in_addr addr;
    char ip_address[INET_ADDRSTRLEN];
    if (rule == NULL || buf == NULL || buf_size < 0) {
        return -1;
    }
    buf_p = buf;
    // hook链
    switch (rule->hook_chain) {
        case NF_HOOK_PREROUTING:
            snprintf(buf_p, (buf_size-(buf_p-buf)), "[PREROUTING] ");
            break;
        case NF_HOOK_LOCALIN:
            snprintf(buf_p, (buf_size-(buf_p-buf)), "[LOCALIN] ");
            break;
        case NF_HOOK_FORWARD:
            snprintf(buf_p, (buf_size-(buf_p-buf)), "[FORWARD] ");
            break;
        case NF_HOOK_LOCALOUT:
            snprintf(buf_p, (buf_size-(buf_p-buf)), "[LOCALOUT] ");
            break;
        case NF_HOOK_POSTROUTING:
            snprintf(buf_p, (buf_size-(buf_p-buf)), "[POSTROUTING] ");
            break;
        case NF_HOOK_NAT:
            snprintf(buf_p, (buf_size-(buf_p-buf)), "[NAT] ");
            break;
    }
    buf_p += strlen(buf_p);
    // 网卡
    if ((rule->rule.match_flags & FILTER_MATCH_INDEV) != 0 || (rule->rule.match_flags & FILTER_MATCH_OUTDEV) != 0) {
        snprintf(buf_p, (buf_size-(buf_p-buf)), "-i ");
        buf_p += strlen(buf_p);
        char devname[32];
        if ((rule->rule.match_flags & FILTER_MATCH_INDEV) != 0) {
            if (get_interface_name(rule->rule.indev, devname, sizeof(devname)) != 0) {
                return -1;
            }
            snprintf(buf_p, (buf_size-(buf_p-buf)), "%s", devname);
            buf_p += strlen(buf_p);
        }
        if ((rule->rule.match_flags & FILTER_MATCH_OUTDEV) != 0) {
            if (get_interface_name(rule->rule.outdev, devname, sizeof(devname)) != 0) {
                return -1;
            }
            snprintf(buf_p, (buf_size-(buf_p-buf)), ":%s", devname);
            buf_p += strlen(buf_p);
        }
        snprintf(buf_p, (buf_size-(buf_p-buf)), " ");
        buf_p += strlen(buf_p);
    }
    // 协议
    if ((rule->rule.match_flags & FILTER_MATCH_PROTO) != 0) {
        switch (rule->rule.protocol) {
            case IPPROTO_ICMP:
                snprintf(buf_p, (buf_size-(buf_p-buf)), "-p ICMP ");
                break;
            case IPPROTO_UDP:
                snprintf(buf_p, (buf_size-(buf_p-buf)), "-p UDP ");
                break;
            case IPPROTO_TCP:
                snprintf(buf_p, (buf_size-(buf_p-buf)), "-p TCP ");
                break;
            default:
                return -1;
        }
        buf_p += strlen(buf_p);
    }
    // 源地址
    if ((rule->rule.match_flags & FILTER_MATCH_SADDR) != 0 || (rule->rule.match_flags & FILTER_MATCH_SPORT) != 0) {
        snprintf(buf_p, (buf_size-(buf_p-buf)), "-s ");
        buf_p += strlen(buf_p);
        // ip
        if ((rule->rule.match_flags & FILTER_MATCH_SADDR) != 0 ) {
            addr.s_addr = rule->rule.saddr;
            if (inet_ntop(AF_INET, &addr, ip_address, INET_ADDRSTRLEN) == NULL) {
                return -1;
            }
            snprintf(buf_p, (buf_size-(buf_p-buf)), "%s/%hhu", ip_address, rule->rule.sprefixlen);
            buf_p += strlen(buf_p);
        }
        // 端口
        if ((rule->rule.match_flags & FILTER_MATCH_SPORT) != 0 ) {
            snprintf(buf_p, (buf_size-(buf_p-buf)), ":%hu", ntohs(rule->rule.sport));
            buf_p += strlen(buf_p);
        }
        snprintf(buf_p, (buf_size-(buf_p-buf)), " ");
        buf_p += strlen(buf_p);
    }
    // 目的地址
    if ((rule->rule.match_flags & FILTER_MATCH_DADDR) != 0 || (rule->rule.match_flags & FILTER_MATCH_DPORT) != 0) {
        snprintf(buf_p, (buf_size-(buf_p-buf)), "-d ");
        buf_p += strlen(buf_p);
        // ip
        if ((rule->rule.match_flags & FILTER_MATCH_DADDR) != 0 ) {
            addr.s_addr = rule->rule.daddr;
            if (inet_ntop(AF_INET, &addr, ip_address, INET_ADDRSTRLEN) == NULL) {
                return -1;
            }
            snprintf(buf_p, (buf_size-(buf_p-buf)), "%s/%hhu", ip_address, rule->rule.dprefixlen);
            buf_p += strlen(buf_p);
        }
        // 端口
        if ((rule->rule.match_flags & FILTER_MATCH_DPORT) != 0 ) {
            snprintf(buf_p, (buf_size-(buf_p-buf)), ":%hu", ntohs(rule->rule.dport));
            buf_p += strlen(buf_p);
        }
        snprintf(buf_p, (buf_size-(buf_p-buf)), " ");
        buf_p += strlen(buf_p);
    }
    // 规则
    snprintf(buf_p, (buf_size-(buf_p-buf)), "-r ");
    buf_p += strlen(buf_p);
    switch (rule->rule.rule_type) {
        case FILTER_ACCEPT:
            snprintf(buf_p, (buf_size-(buf_p-buf)), "ACCEPT");
            buf_p += strlen(buf_p);
            break;
        case FILTER_DROP:
            snprintf(buf_p, (buf_size-(buf_p-buf)), "DROP");
            buf_p += strlen(buf_p);
            break;
        case FILTER_SNAT:
            addr.s_addr = rule->rule.nataddr;
            if (inet_ntop(AF_INET, &addr, ip_address, INET_ADDRSTRLEN) == NULL) {
                return -1;
            }
            snprintf(buf_p, (buf_size-(buf_p-buf)), "SNAT:%s:%hu", ip_address, ntohs(rule->rule.natport));
            buf_p += strlen(buf_p);
            break;
        case FILTER_DNAT:
            addr.s_addr = rule->rule.nataddr;
            if (inet_ntop(AF_INET, &addr, ip_address, INET_ADDRSTRLEN) == NULL) {
                return -1;
            }
            snprintf(buf_p, (buf_size-(buf_p-buf)), "DNAT:%s:%hu", ip_address, ntohs(rule->rule.natport));
            buf_p += strlen(buf_p);
            break;
        default:
            return -1;
    }
    return 0;
}