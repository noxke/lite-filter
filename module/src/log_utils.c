#include <linux/string.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/time.h>

#include "netlink_utils.h"
#include "netlink_msg.h"
#include "module_utils.h"
#include "log_utils.h"

char g_log_file[LOG_FILENAME_SIZE];

int g_log_level = LOG_NONE;
int g_log_kprint_level = LOG_NONE;

static DEFINE_MUTEX(log_mutex);

struct log_work_data {
    struct work_struct work;
    int log_level;
    char log_buffer[LOG_MSG_SIZE];
};

static struct workqueue_struct *log_wq = NULL;

static void log_work_handler(struct work_struct *work) {
    struct file *fp;
    struct timespec64 ts;
    struct tm tm;
    char timestamp[40];
    struct log_work_data *log_work = container_of(work, struct log_work_data, work);

    mutex_lock(&log_mutex);

    if (log_work->log_level >= g_log_kprint_level) {
        switch(log_work->log_level) {
            case LOG_INFO:
                printk(KERN_INFO LOG_PREFIX "[INFO] %s", log_work->log_buffer);
                break;
            case LOG_WARNING:
                printk(KERN_WARNING LOG_PREFIX "[WARNING] %s", log_work->log_buffer);
                break;
            case LOG_ERROR:
                printk(KERN_ERR LOG_PREFIX "[ERROR] %s", log_work->log_buffer);
                break;
            default:
                break;
        }
    }

    while (log_work->log_level >= g_log_level) {
        fp = filp_open(g_log_file, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (IS_ERR(fp)) {
            break;
        }
        // 获取格式化时间
        ktime_get_real_ts64(&ts);
        time64_to_tm(ts.tv_sec, 0, &tm);
        snprintf(timestamp, sizeof(timestamp), "[%04ld-%02d-%02d %02d:%02d:%02d]",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
        kernel_write(fp, timestamp, strlen(timestamp), &fp->f_pos);
        switch(log_work->log_level) {
            case LOG_INFO:
                kernel_write(fp, " [INFO] ", strlen(" [INFO] "), &fp->f_pos);
                break;
            case LOG_WARNING:
                kernel_write(fp, " [WARNING] ", strlen(" [WARNING] "), &fp->f_pos);
                break;
            case LOG_ERROR:
                kernel_write(fp, " [ERROR] ", strlen(" [ERROR] "), &fp->f_pos);
                break;
            default:
                break;
        }
        kernel_write(fp, log_work->log_buffer, strlen(log_work->log_buffer), &fp->f_pos);
        kernel_write(fp, "\n", 1, &fp->f_pos);

        filp_close(fp, NULL);
        break;
    }

    mutex_unlock(&log_mutex);

    kfree(log_work);
}

void async_log(int log_level, const char *format, ...) {
    va_list args;
    struct log_work_data *log_work;
    if (log_wq == NULL) {
        return;
    }

    log_work = kmalloc(sizeof(struct log_work_data), GFP_KERNEL);
    if (log_work == NULL) {
        return;
    }

    log_work->log_level = log_level;

    va_start(args, format);

    vsnprintf(log_work->log_buffer, LOG_MSG_SIZE, format, args);

    INIT_WORK(&log_work->work, log_work_handler);
    queue_work(log_wq, &log_work->work);

    va_end(args);
}

void log_config(LogConfig *conf) {
    struct nl_msg_struct *msg;
    LogConfig *msg_conf;
    if (conf == NULL) {
        return;
    }
    if (conf->config_type == CONF_LOG_SET) {
        g_log_level = conf->log_level;
        g_log_kprint_level = conf->log_kprint_level;
        strncpy(g_log_file, conf->log_file, sizeof(g_log_file));
    }
    else if (conf->config_type == CONF_LOG_GET) {
        msg = (struct nl_msg_struct *)kmalloc(NL_MSG_SIZE(sizeof(LogConfig)), GFP_KERNEL);
        if (msg == NULL) {
            return;
        }
        msg->msg_type = NL_MSG_CONF;
        msg->msg_size = NL_MSG_SIZE(sizeof(LogConfig));
        msg_conf = (LogConfig *)NL_MSG_DATA(msg);
        msg_conf->log_level = g_log_level;
        msg_conf->log_kprint_level = g_log_kprint_level;
        strncpy(msg_conf->log_file, g_log_file, sizeof(msg_conf->log_file));
        nl_send_msg(msg);
    }
}

int log_utils_init(void) {
    memset(g_log_file, 0, sizeof(log_file));
    g_log_level = LOG_INFO;
    g_log_kprint_level = LOG_INFO;
    log_wq = alloc_workqueue("log_wq", WQ_UNBOUND, 1);
    if (log_wq == NULL) {
        return -ENOMEM;
    }
    return 0;
}

void log_utils_exit(void) {
    flush_workqueue(log_wq);
    destroy_workqueue(log_wq);
}