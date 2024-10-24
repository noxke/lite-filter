#ifndef __LOG_UTILS_H__ // __LOG_UTILS_H__
#define __LOG_UTILS_H__
// 统一异步日志接口

#define LOG_PREFIX "lite_filter: "

#define LOG_NONE 255
#define LOG_INFO 0
#define LOG_WARNING 1
#define LOG_ERROR 2

#define LOG_FILENAME_SIZE 256
#define LOG_MSG_SIZE 1000

extern void async_log(int log_level, const char *format, ...);

extern void set_log_sender(void *logger);
extern void set_log_level(int level);
extern void set_log_kprint_level(int level);

extern int log_utils_init(void);
extern void log_utils_exit(void);

#endif // __LOG_UTILS_H__