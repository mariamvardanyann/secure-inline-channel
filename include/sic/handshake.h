#ifndef SIC_HANDSHAKE_H
#define SIC_HANDSHAKE_H

#include "sic/config.h"
#include "sic/crypto.h"

#include <stddef.h>

int sic_handshake_over_fd(int fd, const struct sic_config *config,
                          struct sic_session *session,
                          char *error, size_t error_length);

int sic_handshake_run(const struct sic_config *config,
                      struct sic_session *session,
                      char *error, size_t error_length);

#endif
