#define _POSIX_C_SOURCE 200809L

#include "sic/config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIC_CONFIG_LINE_MAX 1024U

static char *trim(char *text)
{
    char *end;

    while (*text != '\0' && isspace((unsigned char)*text) != 0) {
        ++text;
    }
    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1]) != 0) {
        --end;
    }
    *end = '\0';
    return text;
}

static int parse_u32(const char *text, uint32_t minimum, uint32_t maximum,
                     uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < minimum ||
        parsed > maximum) {
        return -1;
    }
    *value = (uint32_t)parsed;
    return 0;
}

static int hex_value(char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return 10 + character - 'a';
    }
    if (character >= 'A' && character <= 'F') {
        return 10 + character - 'A';
    }
    return -1;
}

static int parse_hex(const char *text, uint8_t *output, size_t capacity,
                     size_t *output_length)
{
    size_t text_length = strlen(text);
    size_t index;

    if (text_length == 0U) {
        *output_length = 0U;
        return 0;
    }
    if ((text_length % 2U) != 0U || text_length / 2U > capacity) {
        return -1;
    }
    for (index = 0U; index < text_length / 2U; ++index) {
        int high = hex_value(text[index * 2U]);
        int low = hex_value(text[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return -1;
        }
        output[index] = (uint8_t)((unsigned int)high * 16U + (unsigned int)low);
    }
    *output_length = text_length / 2U;
    return 0;
}

void sic_config_defaults(struct sic_config *config)
{
    (void)memset(config, 0, sizeof(*config));
    config->control_port = 47000U;
    config->encrypt_queue = 100U;
    config->decrypt_queue = 101U;
    config->replay_window = 128U;
    config->counter_lookahead = 128U;
    config->connect_timeout_seconds = 30U;
    config->log_level = SIC_LOG_INFO;
    (void)snprintf(config->listen_address, sizeof(config->listen_address),
                   "0.0.0.0");
}

static int apply_entry(struct sic_config *config, const char *key,
                       const char *value, unsigned int line_number,
                       char *error, size_t error_length)
{
    uint32_t number;

    if (strcmp(key, "role") == 0) {
        if (strcmp(value, "device1") == 0) {
            config->role = SIC_ROLE_DEVICE1;
        } else if (strcmp(value, "device2") == 0) {
            config->role = SIC_ROLE_DEVICE2;
        } else {
            goto invalid_value;
        }
    } else if (strcmp(key, "peer_address") == 0) {
        if (strlen(value) >= sizeof(config->peer_address)) {
            goto invalid_value;
        }
        (void)snprintf(config->peer_address, sizeof(config->peer_address),
                       "%s", value);
    } else if (strcmp(key, "listen_address") == 0) {
        if (strlen(value) >= sizeof(config->listen_address)) {
            goto invalid_value;
        }
        (void)snprintf(config->listen_address, sizeof(config->listen_address),
                       "%s", value);
    } else if (strcmp(key, "control_port") == 0) {
        if (parse_u32(value, 1U, 65535U, &number) != 0) {
            goto invalid_value;
        }
        config->control_port = (uint16_t)number;
    } else if (strcmp(key, "encrypt_queue") == 0) {
        if (parse_u32(value, 0U, 65535U, &number) != 0) {
            goto invalid_value;
        }
        config->encrypt_queue = (uint16_t)number;
    } else if (strcmp(key, "decrypt_queue") == 0) {
        if (parse_u32(value, 0U, 65535U, &number) != 0) {
            goto invalid_value;
        }
        config->decrypt_queue = (uint16_t)number;
    } else if (strcmp(key, "replay_window") == 0) {
        if (parse_u32(value, 8U, 4096U, &config->replay_window) != 0) {
            goto invalid_value;
        }
    } else if (strcmp(key, "counter_lookahead") == 0) {
        if (parse_u32(value, 1U, 4096U, &config->counter_lookahead) != 0) {
            goto invalid_value;
        }
    } else if (strcmp(key, "connect_timeout_seconds") == 0) {
        if (parse_u32(value, 1U, 3600U, &config->connect_timeout_seconds) != 0) {
            goto invalid_value;
        }
    } else if (strcmp(key, "log_level") == 0) {
        if (strcmp(value, "error") == 0) {
            config->log_level = SIC_LOG_ERROR;
        } else if (strcmp(value, "warn") == 0) {
            config->log_level = SIC_LOG_WARN;
        } else if (strcmp(value, "info") == 0) {
            config->log_level = SIC_LOG_INFO;
        } else if (strcmp(value, "debug") == 0) {
            config->log_level = SIC_LOG_DEBUG;
        } else {
            goto invalid_value;
        }
    } else if (strcmp(key, "psk_hex") == 0) {
        sic_secure_zero(config->psk, sizeof(config->psk));
        if (parse_hex(value, config->psk, sizeof(config->psk),
                      &config->psk_length) != 0) {
            goto invalid_value;
        }
    } else {
        sic_set_error(error, error_length,
                      "line %u: unknown configuration key '%s'",
                      line_number, key);
        return -1;
    }
    return 0;

invalid_value:
    sic_set_error(error, error_length, "line %u: invalid value for '%s'",
                  line_number, key);
    return -1;
}

int sic_config_load(const char *path, struct sic_config *config,
                    char *error, size_t error_length)
{
    FILE *file;
    char line[SIC_CONFIG_LINE_MAX];
    unsigned int line_number = 0U;

    sic_config_defaults(config);
    file = fopen(path, "r");
    if (file == NULL) {
        sic_set_error(error, error_length, "cannot open %s: %s", path,
                      strerror(errno));
        return -1;
    }

    while (fgets(line, (int)sizeof(line), file) != NULL) {
        char *key;
        char *value;
        char *separator;
        char *comment;

        ++line_number;
        if (strchr(line, '\n') == NULL && !feof(file)) {
            sic_set_error(error, error_length, "line %u is too long",
                          line_number);
            (void)fclose(file);
            return -1;
        }
        comment = strchr(line, '#');
        if (comment != NULL) {
            *comment = '\0';
        }
        key = trim(line);
        if (*key == '\0') {
            continue;
        }
        separator = strchr(key, '=');
        if (separator == NULL) {
            sic_set_error(error, error_length,
                          "line %u: expected key=value", line_number);
            (void)fclose(file);
            return -1;
        }
        *separator = '\0';
        value = trim(separator + 1);
        key = trim(key);
        if (*key == '\0' || apply_entry(config, key, value, line_number,
                                         error, error_length) != 0) {
            (void)fclose(file);
            return -1;
        }
    }

    if (ferror(file) != 0) {
        sic_set_error(error, error_length, "error while reading %s", path);
        (void)fclose(file);
        return -1;
    }
    (void)fclose(file);

    if (config->role != SIC_ROLE_DEVICE1 && config->role != SIC_ROLE_DEVICE2) {
        sic_set_error(error, error_length, "configuration must set role");
        return -1;
    }
    if (config->role == SIC_ROLE_DEVICE1 && config->peer_address[0] == '\0') {
        sic_set_error(error, error_length,
                      "device1 configuration must set peer_address");
        return -1;
    }
    if (config->encrypt_queue == config->decrypt_queue) {
        sic_set_error(error, error_length,
                      "encrypt_queue and decrypt_queue must be different");
        return -1;
    }
    if (config->psk_length != 0U && config->psk_length < 16U) {
        sic_set_error(error, error_length,
                      "psk_hex must contain at least 16 bytes (32 hex digits)");
        return -1;
    }
    return 0;
}

void sic_config_clear(struct sic_config *config)
{
    if (config != NULL) {
        sic_secure_zero(config, sizeof(*config));
    }
}
