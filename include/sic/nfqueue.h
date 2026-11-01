#ifndef SIC_NFQUEUE_H
#define SIC_NFQUEUE_H

#include "sic/crypto.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>

enum sic_queue_mode {
    SIC_QUEUE_ENCRYPT = 1,
    SIC_QUEUE_DECRYPT = 2
};

struct sic_queue_stats {
    uint64_t received;
    uint64_t modified;
    uint64_t passed;
    uint64_t dropped;
};

struct sic_queue_context {
    uint16_t queue_number;
    enum sic_queue_mode mode;
    struct sic_session *session;
    struct sic_queue_stats stats;
};

int sic_nfqueue_run(uint16_t encrypt_queue, uint16_t decrypt_queue,
                    struct sic_session *session,
                    volatile sig_atomic_t *stop,
                    struct sic_queue_stats *encrypt_stats,
                    struct sic_queue_stats *decrypt_stats,
                    char *error, size_t error_length);

#endif
