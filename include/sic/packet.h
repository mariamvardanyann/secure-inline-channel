#ifndef SIC_PACKET_H
#define SIC_PACKET_H

#include "sic/crypto.h"

#include <stddef.h>
#include <stdint.h>

enum sic_packet_result {
    SIC_PACKET_ERROR = -1,
    SIC_PACKET_PASS = 0,
    SIC_PACKET_MODIFIED = 1
};

struct sic_packet_view {
    const uint8_t *packet;
    size_t packet_length;
    size_t ip_header_length;
    size_t tcp_header_length;
    size_t payload_offset;
    size_t payload_length;
};

int sic_packet_parse(const uint8_t *packet, size_t packet_length,
                     struct sic_packet_view *view,
                     char *error, size_t error_length);

uint16_t sic_ipv4_checksum(const uint8_t *header, size_t header_length);
uint16_t sic_tcp_checksum(const uint8_t *packet, size_t packet_length);
int sic_packet_checksums_valid(const uint8_t *packet, size_t packet_length);

int sic_packet_encrypt(struct sic_session *session,
                       const uint8_t *packet, size_t packet_length,
                       uint8_t **output, size_t *output_length,
                       uint64_t *used_counter,
                       char *error, size_t error_length);

int sic_packet_decrypt(struct sic_session *session,
                       const uint8_t *packet, size_t packet_length,
                       uint8_t **output, size_t *output_length,
                       uint64_t *used_counter,
                       char *error, size_t error_length);

#endif
