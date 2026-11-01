#ifndef SIC_COMMON_H
#define SIC_COMMON_H

#include <stddef.h>
#include <stdint.h>

#define SIC_VERSION 1U
#define SIC_AES_KEY_LEN 32U
#define SIC_GCM_NONCE_LEN 12U
#define SIC_GCM_TAG_LEN 16U
#define SIC_NONCE_PREFIX_LEN 4U
#define SIC_RANDOM_LEN 32U
#define SIC_SESSION_ID_LEN 16U
#define SIC_MAX_PSK_LEN 64U
#define SIC_MAX_ERROR_LEN 256U

enum sic_role {
    SIC_ROLE_DEVICE1 = 1,
    SIC_ROLE_DEVICE2 = 2
};

enum sic_log_level {
    SIC_LOG_ERROR = 0,
    SIC_LOG_WARN = 1,
    SIC_LOG_INFO = 2,
    SIC_LOG_DEBUG = 3
};

void sic_set_log_level(enum sic_log_level level);
void sic_log(enum sic_log_level level, const char *format, ...);
void sic_secure_zero(void *buffer, size_t length);
void sic_set_error(char *error, size_t error_length, const char *format, ...);

#endif
