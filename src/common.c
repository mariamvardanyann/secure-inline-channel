#define _POSIX_C_SOURCE 200809L

#include "sic/common.h"

#include <openssl/crypto.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static enum sic_log_level current_log_level = SIC_LOG_INFO;

void sic_set_log_level(enum sic_log_level level)
{
    current_log_level = level;
}

void sic_log(enum sic_log_level level, const char *format, ...)
{
    static const char *const names[] = {"ERROR", "WARN", "INFO", "DEBUG"};
    struct timespec now = {0};
    struct tm tm_now;
    char timestamp[32];
    va_list arguments;

    if (level > current_log_level || level < SIC_LOG_ERROR ||
        level > SIC_LOG_DEBUG) {
        return;
    }

    if (clock_gettime(CLOCK_REALTIME, &now) == 0 &&
        gmtime_r(&now.tv_sec, &tm_now) != NULL) {
        (void)strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S",
                       &tm_now);
    } else {
        (void)snprintf(timestamp, sizeof(timestamp), "unknown-time");
    }

    (void)fprintf(stderr, "%s.%03ldZ %-5s ", timestamp,
                  now.tv_nsec / 1000000L, names[level]);
    va_start(arguments, format);
    (void)vfprintf(stderr, format, arguments);
    va_end(arguments);
    (void)fputc('\n', stderr);
}

void sic_secure_zero(void *buffer, size_t length)
{
    if (buffer != NULL && length > 0U) {
        OPENSSL_cleanse(buffer, length);
    }
}

void sic_set_error(char *error, size_t error_length, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_length == 0U) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(error, error_length, format, arguments);
    va_end(arguments);
}
