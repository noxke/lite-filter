#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/slab.h>

#include "log_utils.h"

static int log_level = LOG_NONE;
static int log_kprint_level = LOG_NONE;
static void (*log_sender)(int log_level, char *s) = NULL;

static DEFINE_MUTEX(log_mutex);

struct log_work_data {
    struct work_struct work;
    int log_level;
    char log_buffer[LOG_MSG_SIZE];
};

static struct workqueue_struct *log_wq = NULL;

static void log_work_handler(struct work_struct *work) {
    struct log_work_data *log_work = container_of(work, struct log_work_data, work);

    mutex_lock(&log_mutex);

    if (log_work->log_level >= log_kprint_level) {
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

    if (log_work->log_level >= log_level) {
        if(log_sender != NULL) {
            log_sender(log_work->log_level, log_work->log_buffer);
        }
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

void set_log_level(int level) {
    log_level = level;
}

void set_log_kprint_level(int level) {
    log_kprint_level = level;
}

void set_log_sender(void *logger) {
    if (logger != NULL) {
        log_sender = logger;
    }
}

int log_utils_init(void) {
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