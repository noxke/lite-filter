#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <sys/time.h>

#include "netlink_msg.h"
#include "netlink_utils.h"

int sk_fd;
struct sockaddr_nl src_addr, dest_addr;

struct nlmsg_buf {
    struct nlmsghdr *nlh;
    struct iovec iov;
    struct msghdr msg;
} nlmsg_sender_buf, nlmsg_recver_buf;

pthread_mutex_t send_mutex;

int recv_thread_keep = 0;
pthread_t recv_thread;

static int (*nl_msg_handlers[MAX_NL_MSG_TYPE])(struct nl_msg_struct *msg);

static int nl_msg_handler_default(struct nl_msg_struct *msg) {
    return 0;
}

void *recv_thread_proc(void *null_arg) {
    struct nl_msg_struct *msg;
    unsigned int msg_size;
    memset(nlmsg_recver_buf.nlh, 0, NLMSG_SPACE(NL_MAX_MSG_SIZE));
    nlmsg_recver_buf.nlh->nlmsg_len = NLMSG_SPACE(NL_MAX_MSG_SIZE);
    nlmsg_recver_buf.iov.iov_len = nlmsg_recver_buf.nlh->nlmsg_len;
    while (recv_thread_keep != 0) {
        if (recvmsg(sk_fd, &nlmsg_recver_buf.msg, 0) <= 0)
        {
            continue;
        }
        msg = (struct nl_msg_struct *)NLMSG_DATA(nlmsg_recver_buf.nlh);
        msg_size = nlmsg_recver_buf.nlh->nlmsg_len - NLMSG_HDRLEN;
        if (msg_size > msg->msg_size || msg_size > NL_MAX_MSG_SIZE) {
            continue;
        }
        if (msg->msg_type >= NL_MSG_RAW && msg->msg_type <= NL_MSG_MAX) {
            nl_msg_handlers[msg->msg_type](msg);
        }
        memset(nlmsg_recver_buf.nlh, 0, NLMSG_SPACE(NL_MAX_MSG_SIZE));
        nlmsg_recver_buf.nlh->nlmsg_len = NLMSG_SPACE(NL_MAX_MSG_SIZE);
        nlmsg_recver_buf.iov.iov_len = nlmsg_recver_buf.nlh->nlmsg_len;
    }
    pthread_exit(NULL);
}

int nl_send_msg(struct nl_msg_struct *msg) {
    pthread_mutex_lock(&send_mutex);
    // 发送消息时加锁, 避免发送缓冲区混乱
    memcpy(NLMSG_DATA(nlmsg_sender_buf.nlh), (char *)msg, msg->msg_size);
    nlmsg_sender_buf.nlh->nlmsg_len = NLMSG_SPACE(msg->msg_size);
    nlmsg_sender_buf.iov.iov_len = nlmsg_sender_buf.nlh->nlmsg_len;
    sendmsg(sk_fd, &nlmsg_sender_buf.msg, 0);
    pthread_mutex_unlock(&send_mutex);
    return 0;
}

void nl_send_ack() {
    struct nl_msg_struct msg;
    msg.msg_size = NL_MSG_SIZE(0);
    msg.msg_type = NL_MSG_ACK;
    nl_send_msg(&msg);
}

void netlink_set_msg_handler(NL_MSG_TYPE msg_type, void *handler) {
    if (msg_type >= NL_MSG_RAW && msg_type <= NL_MSG_MAX) {
        nl_msg_handlers[msg_type] = handler;
    }
}

int netlink_init(void) {
    int i;
    struct timeval timeout;
    // 创建Netlink套接字
    sk_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sk_fd < 0) {
        perror("socket");
        goto _fd_init;
    }

    // 设置接收超时
    timeout.tv_sec = NL_RECV_TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(sk_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // 设置源地址
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    // 绑定源地址
    bind(sk_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    // 设置目标地址
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // 发送给内核
    dest_addr.nl_groups = 0;

    // 构造发送器
    nlmsg_sender_buf.nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(NL_MAX_MSG_SIZE));
    if (nlmsg_sender_buf.nlh == NULL) {
        goto _sender_init;
    }
    memset(nlmsg_sender_buf.nlh, 0, NLMSG_SPACE(NL_MAX_MSG_SIZE));
    nlmsg_sender_buf.nlh->nlmsg_len = NLMSG_SPACE(NL_MAX_MSG_SIZE);
    nlmsg_sender_buf.nlh->nlmsg_pid = getpid();
    nlmsg_sender_buf.nlh->nlmsg_flags = 0;

    nlmsg_sender_buf.iov.iov_base = (void *)nlmsg_sender_buf.nlh;
    nlmsg_sender_buf.iov.iov_len = nlmsg_sender_buf.nlh->nlmsg_len;
    memset(&nlmsg_sender_buf.msg, 0, sizeof(nlmsg_sender_buf.msg));
    nlmsg_sender_buf.msg.msg_name = (void *)&dest_addr;
    nlmsg_sender_buf.msg.msg_namelen = sizeof(dest_addr);
    nlmsg_sender_buf.msg.msg_iov = &nlmsg_sender_buf.iov;
    nlmsg_sender_buf.msg.msg_iovlen = 1;

    // 初始化发送缓冲区锁
    pthread_mutex_init(&send_mutex, NULL);

    // 构造接收器
    nlmsg_recver_buf.nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(NL_MAX_MSG_SIZE));
    if (nlmsg_recver_buf.nlh == NULL) {
        goto _recver_init;
    }
    memset(nlmsg_recver_buf.nlh, 0, NLMSG_SPACE(NL_MAX_MSG_SIZE));

    nlmsg_recver_buf.iov.iov_base = (void *)nlmsg_recver_buf.nlh;
    nlmsg_recver_buf.iov.iov_len = nlmsg_recver_buf.nlh->nlmsg_len;
    memset(&nlmsg_recver_buf.msg, 0, sizeof(nlmsg_recver_buf.msg));
    nlmsg_recver_buf.msg.msg_name = (void *)&dest_addr;
    nlmsg_recver_buf.msg.msg_namelen = sizeof(dest_addr);
    nlmsg_recver_buf.msg.msg_iov = &nlmsg_recver_buf.iov;
    nlmsg_recver_buf.msg.msg_iovlen = 1;

    // 初始化消息处理器
    for (i = 0; i < MAX_NL_MSG_TYPE; i++) {
        nl_msg_handlers[i] = nl_msg_handler_default;
    }

    // 创建接收线程
    if (pthread_create(&recv_thread, NULL, recv_thread_proc, NULL) != 0) {
        goto _recver_init;
    }
    recv_thread_keep = 1;
    // pthread_join(recv_thread, NULL);

    goto _all_init;

_thread_init:
_handler_init:
    free(nlmsg_recver_buf.nlh);
_recver_init:
    free(nlmsg_sender_buf.nlh);
_sender_init:
    close(sk_fd);
_fd_init:
    return -1;
_all_init:
    return 0;
}

void netlink_exit(void) {
    pthread_mutex_destroy(&send_mutex);
    free(nlmsg_recver_buf.nlh);
    free(nlmsg_sender_buf.nlh);
    close(sk_fd);
    return;
}