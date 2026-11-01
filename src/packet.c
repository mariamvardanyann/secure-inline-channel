#define _DEFAULT_SOURCE

#include "sic/packet.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdlib.h>
#include <string.h>

#define SIC_MAX_HEADER_BYTES 120U
#define SIC_AAD_PREFIX_BYTES (4U + SIC_SESSION_ID_LEN)

static uint32_t checksum_add(const uint8_t *data, size_t length,
                             uint32_t sum)
{
    size_t index = 0U;

    while (index + 1U < length) {
        sum += ((uint32_t)data[index] << 8U) | data[index + 1U];
        index += 2U;
    }
    if (index < length) {
        sum += (uint32_t)data[index] << 8U;
    }
    return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    return htons((uint16_t)(~sum & 0xffffU));
}

int sic_packet_parse(const uint8_t *packet, size_t packet_length,
                     struct sic_packet_view *view,
                     char *error, size_t error_length)
{
    const struct iphdr *ip;
    const struct tcphdr *tcp;
    size_t ip_header_length;
    size_t tcp_header_length;
    size_t total_length;
    uint16_t fragment;

    if (packet == NULL || view == NULL || packet_length < sizeof(struct iphdr)) {
        sic_set_error(error, error_length, "packet is shorter than IPv4 header");
        return -1;
    }

    ip = (const struct iphdr *)(const void *)packet;
    if (ip->version != 4U) {
        sic_set_error(error, error_length, "packet is not IPv4");
        return -1;
    }
    ip_header_length = (size_t)ip->ihl * 4U;
    if (ip_header_length < sizeof(struct iphdr) ||
        ip_header_length > 60U || packet_length < ip_header_length) {
        sic_set_error(error, error_length, "invalid IPv4 header length");
        return -1;
    }
    total_length = ntohs(ip->tot_len);
    if (total_length < ip_header_length + sizeof(struct tcphdr) ||
        total_length > packet_length) {
        sic_set_error(error, error_length, "invalid IPv4 total length");
        return -1;
    }
    if (ip->protocol != IPPROTO_TCP) {
        sic_set_error(error, error_length, "packet is not TCP");
        return -1;
    }
    fragment = ntohs(ip->frag_off);
    if ((fragment & (IP_MF | IP_OFFMASK)) != 0U) {
        sic_set_error(error, error_length,
                      "fragmented IPv4 packets are not supported");
        return -1;
    }

    tcp = (const struct tcphdr *)(const void *)(packet + ip_header_length);
    tcp_header_length = (size_t)tcp->doff * 4U;
    if (tcp_header_length < sizeof(struct tcphdr) ||
        tcp_header_length > 60U ||
        total_length < ip_header_length + tcp_header_length) {
        sic_set_error(error, error_length, "invalid TCP header length");
        return -1;
    }

    view->packet = packet;
    view->packet_length = total_length;
    view->ip_header_length = ip_header_length;
    view->tcp_header_length = tcp_header_length;
    view->payload_offset = ip_header_length + tcp_header_length;
    view->payload_length = total_length - view->payload_offset;
    return 0;
}

uint16_t sic_ipv4_checksum(const uint8_t *header, size_t header_length)
{
    return checksum_finish(checksum_add(header, header_length, 0U));
}

uint16_t sic_tcp_checksum(const uint8_t *packet, size_t packet_length)
{
    const struct iphdr *ip;
    size_t ip_header_length;
    size_t total_length;
    size_t tcp_length;
    uint8_t pseudo_tail[4];
    uint32_t sum = 0U;

    if (packet == NULL || packet_length < sizeof(struct iphdr)) {
        return 0xffffU;
    }
    ip = (const struct iphdr *)(const void *)packet;
    ip_header_length = (size_t)ip->ihl * 4U;
    total_length = ntohs(ip->tot_len);
    if (ip->version != 4U || ip_header_length < sizeof(struct iphdr) ||
        total_length < ip_header_length || total_length > packet_length) {
        return 0xffffU;
    }
    tcp_length = total_length - ip_header_length;
    sum = checksum_add(packet + 12U, 8U, sum);
    pseudo_tail[0] = 0U;
    pseudo_tail[1] = IPPROTO_TCP;
    pseudo_tail[2] = (uint8_t)(tcp_length >> 8U);
    pseudo_tail[3] = (uint8_t)(tcp_length & 0xffU);
    sum = checksum_add(pseudo_tail, sizeof(pseudo_tail), sum);
    sum = checksum_add(packet + ip_header_length, tcp_length, sum);
    return checksum_finish(sum);
}

int sic_packet_checksums_valid(const uint8_t *packet, size_t packet_length)
{
    struct sic_packet_view view;
    char error[64];

    if (sic_packet_parse(packet, packet_length, &view, error,
                         sizeof(error)) != 0) {
        return 0;
    }
    if (sic_ipv4_checksum(packet, view.ip_header_length) != 0U) {
        return 0;
    }
    return sic_tcp_checksum(packet, view.packet_length) == 0U;
}

static int build_aad(const struct sic_session *session,
                     const uint8_t *packet,
                     const struct sic_packet_view *view,
                     size_t plaintext_total_length,
                     uint8_t aad[SIC_AAD_PREFIX_BYTES + SIC_MAX_HEADER_BYTES],
                     size_t *aad_length,
                     char *error, size_t error_length)
{
    struct iphdr *aad_ip;
    struct tcphdr *aad_tcp;
    size_t headers_length = view->ip_header_length + view->tcp_header_length;

    if (headers_length > SIC_MAX_HEADER_BYTES ||
        plaintext_total_length > UINT16_MAX) {
        sic_set_error(error, error_length, "header or packet length is invalid");
        return -1;
    }
    (void)memcpy(aad, "SIC1", 4U);
    (void)memcpy(aad + 4U, session->session_id, SIC_SESSION_ID_LEN);
    (void)memcpy(aad + SIC_AAD_PREFIX_BYTES, packet,
                 view->ip_header_length);
    (void)memcpy(aad + SIC_AAD_PREFIX_BYTES + view->ip_header_length,
                 packet + view->ip_header_length, view->tcp_header_length);

    aad_ip = (struct iphdr *)(void *)(aad + SIC_AAD_PREFIX_BYTES);
    aad_tcp = (struct tcphdr *)(void *)(aad + SIC_AAD_PREFIX_BYTES +
                                        view->ip_header_length);
    aad_ip->tot_len = htons((uint16_t)plaintext_total_length);
    aad_ip->ttl = 0U; /* A router legitimately changes TTL between devices. */
    aad_ip->check = 0U;
    aad_tcp->check = 0U;
    *aad_length = SIC_AAD_PREFIX_BYTES + headers_length;
    return 0;
}

static void update_lengths_and_checksums(uint8_t *packet, size_t packet_length)
{
    struct iphdr *ip = (struct iphdr *)(void *)packet;
    struct tcphdr *tcp =
        (struct tcphdr *)(void *)(packet + (size_t)ip->ihl * 4U);

    ip->tot_len = htons((uint16_t)packet_length);
    ip->check = 0U;
    tcp->check = 0U;
    ip->check = sic_ipv4_checksum(packet, (size_t)ip->ihl * 4U);
    tcp->check = sic_tcp_checksum(packet, packet_length);
}

int sic_packet_encrypt(struct sic_session *session,
                       const uint8_t *packet, size_t packet_length,
                       uint8_t **output, size_t *output_length,
                       uint64_t *used_counter,
                       char *error, size_t error_length)
{
    struct sic_packet_view view;
    uint8_t aad[SIC_AAD_PREFIX_BYTES + SIC_MAX_HEADER_BYTES];
    size_t aad_length;
    size_t encrypted_length;
    uint8_t *result;
    uint8_t *tag;

    if (output == NULL || output_length == NULL) {
        sic_set_error(error, error_length, "output arguments are null");
        return SIC_PACKET_ERROR;
    }
    *output = NULL;
    *output_length = 0U;
    if (sic_packet_parse(packet, packet_length, &view, error,
                         error_length) != 0) {
        return SIC_PACKET_ERROR;
    }
    if (view.payload_length == 0U) {
        return SIC_PACKET_PASS;
    }
    if (view.packet_length > UINT16_MAX - SIC_GCM_TAG_LEN) {
        sic_set_error(error, error_length,
                      "packet is too large for the AES-GCM tag");
        return SIC_PACKET_ERROR;
    }
    if (build_aad(session, packet, &view, view.packet_length, aad,
                  &aad_length, error, error_length) != 0) {
        return SIC_PACKET_ERROR;
    }

    encrypted_length = view.packet_length + SIC_GCM_TAG_LEN;
    result = malloc(encrypted_length);
    if (result == NULL) {
        sic_set_error(error, error_length, "cannot allocate encrypted packet");
        return SIC_PACKET_ERROR;
    }
    (void)memcpy(result, packet, view.payload_offset);
    tag = result + view.payload_offset + view.payload_length;
    if (sic_session_encrypt(session, aad, aad_length,
                            packet + view.payload_offset, view.payload_length,
                            result + view.payload_offset, tag, used_counter,
                            error, error_length) != 0) {
        sic_secure_zero(result, encrypted_length);
        free(result);
        return SIC_PACKET_ERROR;
    }
    update_lengths_and_checksums(result, encrypted_length);
    *output = result;
    *output_length = encrypted_length;
    return SIC_PACKET_MODIFIED;
}

int sic_packet_decrypt(struct sic_session *session,
                       const uint8_t *packet, size_t packet_length,
                       uint8_t **output, size_t *output_length,
                       uint64_t *used_counter,
                       char *error, size_t error_length)
{
    struct sic_packet_view view;
    uint8_t aad[SIC_AAD_PREFIX_BYTES + SIC_MAX_HEADER_BYTES];
    size_t aad_length;
    size_t plaintext_payload_length;
    size_t plaintext_total_length;
    const uint8_t *tag;
    uint8_t *result;

    if (output == NULL || output_length == NULL) {
        sic_set_error(error, error_length, "output arguments are null");
        return SIC_PACKET_ERROR;
    }
    *output = NULL;
    *output_length = 0U;
    if (sic_packet_parse(packet, packet_length, &view, error,
                         error_length) != 0) {
        return SIC_PACKET_ERROR;
    }
    if (view.payload_length == 0U) {
        return SIC_PACKET_PASS;
    }
    if (view.payload_length <= SIC_GCM_TAG_LEN) {
        sic_set_error(error, error_length,
                      "protected payload is too short for ciphertext and tag");
        return SIC_PACKET_ERROR;
    }

    plaintext_payload_length = view.payload_length - SIC_GCM_TAG_LEN;
    plaintext_total_length = view.packet_length - SIC_GCM_TAG_LEN;
    if (build_aad(session, packet, &view, plaintext_total_length, aad,
                  &aad_length, error, error_length) != 0) {
        return SIC_PACKET_ERROR;
    }
    result = malloc(plaintext_total_length);
    if (result == NULL) {
        sic_set_error(error, error_length, "cannot allocate decrypted packet");
        return SIC_PACKET_ERROR;
    }
    (void)memcpy(result, packet, view.payload_offset);
    tag = packet + view.payload_offset + plaintext_payload_length;
    if (sic_session_decrypt(session, aad, aad_length,
                            packet + view.payload_offset,
                            plaintext_payload_length, tag,
                            result + view.payload_offset, used_counter,
                            error, error_length) != 0) {
        sic_secure_zero(result, plaintext_total_length);
        free(result);
        return SIC_PACKET_ERROR;
    }
    update_lengths_and_checksums(result, plaintext_total_length);
    *output = result;
    *output_length = plaintext_total_length;
    return SIC_PACKET_MODIFIED;
}
