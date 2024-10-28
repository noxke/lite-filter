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

typedef struct {
    int config_type;
    int log_level;
    int log_kprint_level;
    char log_file[LOG_FILENAME_SIZE];
}LogConfig;

extern int log_level;
extern int log_kprint_level;
extern char log_file[LOG_FILENAME_SIZE];

extern void async_log(int log_level, const char *format, ...);

extern void log_config(LogConfig *conf);

extern int log_utils_init(void);
extern void log_utils_exit(void);

#endif // __LOG_UTILS_H__