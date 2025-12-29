// common/src/logger.c
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "logger.h"
//日誌檔案的檔案指標
static FILE *log_file = NULL;

//初始化日誌檔案,檔名根據日期時間生成
void init_logger() {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char filename[64];
    //檔名格式: log_%Y%m%d_%H%M%S.txt
    strftime(filename, sizeof(filename), "log_%Y%m%d_%H%M%S.txt",t);
    
    log_file = fopen(filename, "a");
    if(log_file == NULL){
        perror("CAN NOT OPEN LOGGER FILE");
    }else {
        printf("LOGGING TO FILE: %s\n", filename);
}
}

// 輸出不同種類的日誌訊息的函式
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

    if(log_file != NULL){
        fprintf(log_file, "%s %s ", time_str, level_str);
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        fprintf(log_file, "\n");
        fflush(log_file); //強制寫入硬碟
    }
}

void close_logger() {
    if(log_file) {
        fclose(log_file);
    }
}
