#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/semaphore.h>
#include <linux/time.h>
#include <linux/timer.h>

#include "log_utils.h"
#include "netlink_msg.h"
#include "netlink_utils.h"
#include "module_utils.h"
#include "netfilter_hook.h"
#include "filter_conn_utils.h"

#define addr4_match(a1, a2, prefixlen) \
    (((prefixlen) == 0 || ((((a1) ^ (a2)) & htonl(~0UL << (32 - (prefixlen)))) == 0)) ? 0 : -1)

int get_tcp_status_v4(FilterConnNodeV4 *conn, IpPackInfoV4 *info, struct sk_buff *skb) {
    struct tcphdr *tcp_header;
    int is_tcp_c2s;
    int new_status;
    if (conn == NULL || info == NULL || skb == NULL) {
        return -1;
    }
    // 提取tcp头
    tcp_header = tcp_hdr(skb);
    // 检查报文是否为为客户端->服务器
    // 第一个报文默认为客户端->服务器
    // 后续报文中，与第一个报文方向相同为客户端->服务器，方向相反为服务器->客户端
    if (conn->ip_info.saddr == info->saddr && conn->ip_info.sport == info->sport && conn->ip_info.daddr == info->daddr && conn->ip_info.dport == info->dport) {
        is_tcp_c2s = 1;
    }
    else if (conn->ip_info.daddr == info->saddr && conn->ip_info.dport == info->sport && conn->ip_info.saddr == info->daddr && conn->ip_info.sport == info->dport) {
        is_tcp_c2s = 0;
    }
    else {
        // 匹配错误，不可能出现的情况
        return FILTER_STATUS_NONE;
    }
    // async_log(LOG_INFO, "### %pI4->%pI4 syn=%d ack=%d fin=%d ###", &(info->saddr), &(info->daddr), tcp_header->syn, tcp_header->ack, tcp_header->fin);
    new_status = FILTER_STATUS_NONE;
    switch (conn->status) {
        case FILTER_STATUS_NONE:
        case FILTER_STATUS_TCP_CLOSED:
            if (tcp_header->syn == 1) {
                if (is_tcp_c2s == 0) {
                    // 接收到syn=1，客户端、服务器身份发生改变，syn=1由客户端发往服务器
                    memcpy(&(conn->ip_info), info, sizeof(conn->ip_info));
                }
                new_status = FILTER_STATUS_TCP_SYN_SENT;
            }
            break;
        case FILTER_STATUS_TCP_SYN_SENT:
            if (tcp_header->syn == 1 && tcp_header->ack == 1) {
                if (is_tcp_c2s == 0) {
                    new_status = FILTER_STATUS_TCP_ESTABLISHED;
                }
            }
            else {
                new_status = FILTER_STATUS_TCP_SYN_SENT;
            }
            break;
        case FILTER_STATUS_TCP_SYN_RECEIVED:
            if (tcp_header->ack == 1) {
                if (is_tcp_c2s == 1) {
                    new_status = FILTER_STATUS_TCP_ESTABLISHED;
                }
            }
            break;
        case FILTER_STATUS_TCP_ESTABLISHED:
            if (tcp_header->fin == 1 && tcp_header->ack == 0) {
                // 接收到fin=1，客户端、服务器身份发生改变，fin=1由客户端发往服务器
                memcpy(&(conn->ip_info), info, sizeof(conn->ip_info));
                new_status = FILTER_STATUS_TCP_LAST_ACK;
            }
            else if (tcp_header->fin == 1 && tcp_header->ack == 1) {
                // 接收到fin=1，客户端、服务器身份发生改变，fin=1由客户端发往服务器
                memcpy(&(conn->ip_info), info, sizeof(conn->ip_info));
                new_status = FILTER_STATUS_TCP_FIN_WAIT;
            }
            else {
                new_status =FILTER_STATUS_TCP_ESTABLISHED;
            }
            break;
        case FILTER_STATUS_TCP_FIN_WAIT:
            if (is_tcp_c2s == 0 && tcp_header->fin == 1) {
                new_status = FILTER_STATUS_TCP_TIME_WAIT;
            }
            else {
                new_status = FILTER_STATUS_TCP_FIN_WAIT;
            }
            break;
        case FILTER_STATUS_TCP_CLOSE_WAIT:
            if (tcp_header->fin == 1 && tcp_header->ack == 1) {
                new_status = FILTER_STATUS_TCP_LAST_ACK;
            }
            break;
        case FILTER_STATUS_TCP_LAST_ACK:// async_log(LOG_INFO, "### %pI4->%pI4 syn=%d ack=%d fin=%d ###", &(info->saddr), &(info->daddr), tcp_header->syn, tcp_header->ack, tcp_header->fin);
            if (tcp_header->ack == 1) {
                new_status = FILTER_STATUS_TCP_CLOSED;
            }
            break;
        case FILTER_STATUS_TCP_TIME_WAIT:
            new_status = FILTER_STATUS_TCP_CLOSED;
            break;
    }

    // 状态机
    return new_status;
}

int get_ip_pack_status_v4(FilterConnNodeV4 *conn, IpPackInfoV4 *info, struct sk_buff *skb) {
    struct iphdr *ip_header;
    if (conn == NULL || info == NULL || skb == NULL) {
        return -1;
    }
    ip_header = ip_hdr(skb);
    switch (ip_header->protocol) {
        case IPPROTO_ICMP:
            // ICMP无状态机
            return FILTER_STATUS_ICMP;
            break;
        case IPPROTO_TCP:
            // TCP状态机
            return get_tcp_status_v4(conn, info, skb);
            break;
        case IPPROTO_UDP:
            // UDP无状态机
            return FILTER_STATUS_UDP;
            break;
        default:
            break;
    }
    return FILTER_STATUS_NONE;
}

void status_format(FilterConnNodeV4 *conn, char *buf, int size) {
    char *status_str;
    IpPackInfoV4 *info;
    struct timespec64 current_time;
    long long int expired_sec;
    if (conn == NULL || buf == NULL) {
        return;
    }
    // 获取当前时间
    ktime_get_real_ts64(&current_time);
    expired_sec = conn->expire_time - current_time.tv_sec;
    info = &(conn->ip_info);
    memset(buf, 0, size);
    switch (conn->status) {
        case FILTER_STATUS_NONE:
            status_str = "NONE";
            break;
        case FILTER_STATUS_ICMP:
            status_str = "ICMP";
            break;
        case FILTER_STATUS_UDP:
            status_str = "UDP";
            break;
        case FILTER_STATUS_TCP_CLOSED:
            status_str = "TCP_CLOSED";
            break;
        case FILTER_STATUS_TCP_SYN_SENT:
            status_str = "TCP_SYN_SENT";
            break;
        case FILTER_STATUS_TCP_SYN_RECEIVED:
            status_str = "TCP_SYN_RECEIVED";
            break;
        case FILTER_STATUS_TCP_ESTABLISHED:
            status_str = "TCP_ESTABLISHED";
            break;
        case FILTER_STATUS_TCP_FIN_WAIT:
            status_str = "TCP_FIN_WAIT";
            break;
        case FILTER_STATUS_TCP_CLOSE_WAIT:
            status_str = "TCP_CLOSE_WAIT";
            break;
        case FILTER_STATUS_TCP_LAST_ACK:
            status_str = "TCP_LAST_ACK";
            break;
        case FILTER_STATUS_TCP_TIME_WAIT:
            status_str = "TCP_TIME_WAI";
            break;
        default:
            status_str = "NONE";
            break;
    }
    switch (conn->protocol) {
        case IPPROTO_ICMP:
            snprintf(buf, size, "%pI4->%pI4 %s expired: %llds",  &(info->saddr), &(info->daddr), status_str, expired_sec);
            break;
        case IPPROTO_TCP:
            snprintf(buf, size, "%pI4:%hu->%pI4:%hu %s expired: %llds", &(info->saddr), ntohs(info->sport), &(info->daddr), ntohs(info->dport), status_str, expired_sec);
            break;
        case IPPROTO_UDP:
            snprintf(buf, size, "%pI4:%hu->%pI4:%hu %s expired: %llds", &(info->saddr), ntohs(info->sport), &(info->daddr), ntohs(info->dport), status_str, expired_sec);
            break;
        default:
            break;
    }
}

FilterConnNodeV4 *filter_conn_match_v4(IpPackInfoV4 *info, struct sk_buff *skb) {
    char status_str[DEFAULT_STR_SIZE];
    FilterConnNodeV4 *next;
    int next_status;
    struct timespec64 current_time;
    u64 current_sec;
    if (info == NULL || skb == NULL) {
        return NULL;
    }

    // 获取当前时间
    ktime_get_real_ts64(&current_time);
    current_sec = current_time.tv_sec;
    next = nf_hook_conn_link;
    while (next != NULL) {
        // 检查释放过期
        if (next->expire_time < current_sec) {
            next = next->next;
            continue;
        }
        // 检查协议
        if (next->protocol != info->protocol) {
            next = next->next;
            continue;
        }
        if (next->protocol == IPPROTO_ICMP) {
            // ICMP不检查端口
            // 检查ip是否匹配
            if (next->ip_info.saddr == info->saddr && next->ip_info.daddr == info->daddr) {
                break;
            }
            else if (next->ip_info.daddr == info->saddr && next->ip_info.saddr == info->daddr) {
                break;
            }
        }
        else if (next->protocol == IPPROTO_UDP || next->protocol == IPPROTO_TCP) {
            // UDP TCP需要同时检查ip与端口
            if (next->ip_info.saddr == info->saddr && next->ip_info.sport == info->sport && next->ip_info.daddr == info->daddr && next->ip_info.dport == info->dport) {
                break;
            }
            else if (next->ip_info.daddr == info->saddr && next->ip_info.dport == info->sport && next->ip_info.saddr == info->daddr && next->ip_info.sport == info->dport) {
                break;
            }
        }
        next = next->next;
    }
    if (next != NULL) {
        // 检查状态是否异常
        next_status = get_ip_pack_status_v4(next, info, skb);
        if (next_status == FILTER_STATUS_NONE) {
            // 异常状态丢弃
            status_format(next, status_str, sizeof(status_str));
            async_log(LOG_INFO, "[FILTER] [CONN_DROP] %s", status_str);
            next = CONN_DROP;
        }
        else {
            // 匹配成功，更新状态和过期时间
            next->expire_time = current_sec + EXPIRE_TIME;
            next->status = next_status;
            status_format(next, status_str, sizeof(status_str));
            async_log(LOG_INFO, "[FILTER] [CONN_MATCH] %s", status_str);
        }
    }

    return next;
}

int filter_conn_insert_v4(IpPackInfoV4 *info, struct sk_buff *skb) {
    char status_str[DEFAULT_STR_SIZE];
    FilterConnNodeV4 *next;
    FilterConnNodeV4 *new_node;
    struct timespec64 current_time;
    u64 current_sec;
    if (info == NULL || skb == NULL) {
        return -1;
    }

    new_node = (FilterConnNodeV4 *)kmalloc(sizeof(FilterConnNodeV4), GFP_KERNEL);
    if (new_node == NULL) {
        return -1;
    }
    // 获取当前时间
    ktime_get_real_ts64(&current_time);
    current_sec = current_time.tv_sec;
    memcpy(&(new_node->ip_info), info, sizeof(new_node->ip_info));
    new_node->protocol = info->protocol;
    // 设置过期时间
    new_node->expire_time = current_sec + EXPIRE_TIME;
    new_node->status = FILTER_STATUS_NONE;
    new_node->status = get_ip_pack_status_v4(new_node, info, skb);
    // 插入到链表末尾
    if (nf_hook_conn_link == NULL) {
        nf_hook_conn_link = new_node;
    }
    else {
        next = nf_hook_conn_link;
        while (next->next != NULL) {
            next = next->next;
        }
        next->next = new_node;
    }
    status_format(new_node, status_str, sizeof(status_str));
    async_log(LOG_INFO, "[FILTER] [CONN_NEW] %s", status_str);

    return 0;
}

void filter_conn_clear_v4(FilterConnNodeV4 *conn_link) {
    FilterConnNodeV4 *rm_node;
    FilterConnNodeV4 *next;
    if (conn_link == NULL) {
        return;
    }

    next = conn_link;
    while (next != NULL) {
        rm_node = next;
        next = rm_node->next;
        kfree(rm_node);
    }
}

void filter_conn_dump_v4(FilterConnNodeV4 *conn_link, const char *tmpfile) {
    char status_str[DEFAULT_STR_SIZE];
    FilterConnNodeV4 *next;
    struct nl_msg_struct *msg;
    ConnConfig *msg_conf;
    struct file *fp;
    if (tmpfile == NULL) {
        return;
    }
    fp = filp_open(tmpfile, O_WRONLY | O_CREAT, 0600);
    if (IS_ERR(fp)) {
        return;
    }
    next = conn_link;
    msg = (struct nl_msg_struct *)kmalloc(NL_MSG_SIZE(sizeof(ConnConfig)), GFP_KERNEL);
    if (msg == NULL) {
        filp_close(fp, NULL);
        return;
    }
    msg->msg_type = NL_MSG_CONF;
    msg->msg_size = NL_MSG_SIZE(sizeof(ConnConfig));
    msg_conf = (ConnConfig *)NL_MSG_DATA(msg);
    msg_conf->config_type = CONF_CONN_DUMP;
    while (next != NULL) {
        status_format(next, status_str, sizeof(status_str));
        kernel_write(fp, status_str, strlen(status_str), &fp->f_pos);
        kernel_write(fp, "\n", 1, &fp->f_pos);
        next = next->next;
    }
    filp_close(fp, NULL);
    // 回应用户态程序dump结束
    memset(&(msg_conf->conf_str), 0, sizeof(msg_conf->conf_str));
    nl_send_msg(msg);
    kfree(msg);
}

void filter_conn_config(ConnConfig *conf) {
    // 获取写sem
    down_write(&nf_hook_conn_rwsem);
    switch (conf->config_type) {
        case CONF_CONN_CLEAR:
            async_log(LOG_WARNING, "[MANAGE] Clear connections");
            filter_conn_clear_v4(nf_hook_conn_link);
            nf_hook_conn_link = NULL;
            break;
        case CONF_CONN_DUMP:
            async_log(LOG_WARNING, "[MANAGE] Dump connections");
            filter_conn_dump_v4(nf_hook_conn_link, conf->conf_str);
            break;
    }
    // 释放写sem
    up_write(&nf_hook_conn_rwsem);
}


void filter_conn_updater(struct timer_list *t) {
    struct timespec64 current_time;
    u64 current_sec;
    FilterConnNodeV4 *next;
    FilterConnNodeV4 *prev;
    char status_str[DEFAULT_STR_SIZE];

    // 获取写sem
    down_write(&nf_hook_conn_rwsem);
    // 获取当前时间
    ktime_get_real_ts64(&current_time);
    current_sec = current_time.tv_sec;

    next = nf_hook_conn_link;
    prev = NULL;
    while (next != NULL) {
        if (next->expire_time < current_sec) {
            status_format(next, status_str, sizeof(status_str));
            async_log(LOG_INFO, "[FILTER] [CONN_EXPIRED] %s", status_str);
            // 过期移除
            if (prev == NULL) {
                nf_hook_conn_link = next->next;
                kfree(next);
                next = nf_hook_conn_link;
            }
            else {
                prev->next = next->next;
                kfree(next);
                next = prev->next;
            }
            continue;
        }
        prev = next;
        next = next->next;
    }
    
    // 释放写sem
    up_write(&nf_hook_conn_rwsem);
    // 设置下一次定时任务
    mod_timer(t, jiffies + msecs_to_jiffies(UPDATE_TIME));
}