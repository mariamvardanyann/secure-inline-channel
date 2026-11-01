#ifndef SIC_CONFIG_H
#define SIC_CONFIG_H

#include "sic/common.h"

#include <stddef.h>
#include <stdint.h>

struct sic_config {
    enum sic_role role;
    char peer_address[256];
    char listen_address[256];
    uint16_t control_port;
    uint16_t encrypt_queue;
    uint16_t decrypt_queue;
    uint32_t replay_window;
    uint32_t counter_lookahead;
    uint32_t connect_timeout_seconds;
    enum sic_log_level log_level;
    uint8_t psk[SIC_MAX_PSK_LEN];
    size_t psk_length;
};

void sic_config_defaults(struct sic_config *config);
int sic_config_load(const char *path, struct sic_config *config,
                    char *error, size_t error_length);
void sic_config_clear(struct sic_config *config);

#endif
