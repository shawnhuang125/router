#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "logger.h"

void log_message(LogLevel level, const char *format, ...) {
    //to get current time
    time_t now;
    time(&now);
    char *time_str = ctime(&now);
    time_str[24] = '\0';

    const char *level_str;
    switch (level) {
        case LOG_INFO:    level_str = "[INFO]"; break;
        case LOG_WARNING: level_str = "[WARN]"; break;
        case LOG_ERROR:   level_str = "[ERROR]"; break;
        default:          level_str = "[LOG]"; break;
    }
    // print the begining of logger (Time + Level)
    printf("%s %s ", time_str, level_str);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}
