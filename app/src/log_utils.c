#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>

#include "netlink_utils.h"
#include "log_utils.h"

struct LogMessage {
    int log_level;
    char log_buffer[LOG_MSG_SIZE];
};

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;


// 异步日志处理线程
void *log_thread(void *arg) {
    struct LogMessage *message = (struct LogMessage *)arg;
    pthread_mutex_lock(&log_mutex);

    printf("%s\n", message->log_buffer);

    pthread_mutex_unlock(&log_mutex);
    free(message);
    return NULL;
}

// 异步日志接口
void async_log(int log_level, const char *format, ...) {
    struct LogMessage *message;
    va_list args;
    pthread_t tid;

    message = (struct LogMessage *)malloc(sizeof(struct LogMessage));
    if (message == NULL)
    {
        return;
    }

    message->log_level = log_level;

    va_start(args, format);

    vsnprintf(message->log_buffer, LOG_MSG_SIZE, format, args);

    pthread_create(&tid, NULL, log_thread, message);
    pthread_detach(tid);

    va_end(args);
}

// 普通日志接口
void lf_log(int log_level, const char *format, ...) {
    struct LogMessage *message;
    va_list args;

    message = (struct LogMessage *)malloc(sizeof(struct LogMessage));
    if (message == NULL)
    {
        return;
    }

    message->log_level = log_level;

    va_start(args, format);

    vsnprintf(message->log_buffer, LOG_MSG_SIZE, format, args);

    printf("%s\n", message->log_buffer);

    va_end(args);
}