#ifndef __NETLINK_MSG_H__ // __NETLINK_MSG_H__
#define __NETLINK_MSG_H__
// netlink消息定义

// 消息最大长度
#define NL_MAX_MSG_SIZE 1024

// 消息类型
#define MAX_NL_MSG_TYPE 32
typedef enum nl_msg_type_enum {
    NL_MSG_RAW = 0,
    NL_MSG_ALIVE = 1,   // 存活检测
    NL_MSG_ACK = 2,     // 确认回复
    NL_MSG_ERR = 3,     // 错误回复
    NL_MSG_CONF = 21,   // 配置消息
    NL_MSG_MAX = 31
} NL_MSG_TYPE;

struct nl_msg_struct {
    int msg_type;
    unsigned int msg_size;  // 包含头部大小
};

#define NL_MSG_SIZE(size) (sizeof(struct nl_msg_struct)+(size))
#define NL_MSG_DATA(msg) ((char *)(msg)+sizeof(struct nl_msg_struct))

#endif // __NETLINK_MSG_H__