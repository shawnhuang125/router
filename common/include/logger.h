#ifndef LOGGER_H
#define LOGGER_H

// define logger level
typedef enum {
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LogLevel;

// define function: print logger
void log_message(LogLevel level, const char *format, ...);

# endif

// the logger system is made there
