#define _GNU_SOURCE

#include "sic/nfqueue.h"

#include "sic/packet.h"

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SIC_NETLINK_BUFFER_SIZE 131072U
#define SIC_QUEUE_MAX_LENGTH 4096U

static int packet_callback(struct nfq_q_handle *queue,
                           struct nfgenmsg *message,
                           struct nfq_data *data, void *callback_data)
{
    struct sic_queue_context *context = callback_data;
    struct nfqnl_msg_packet_hdr *header;
    unsigned char *payload = NULL;
    uint8_t *output = NULL;
    size_t output_length = 0U;
    uint64_t counter = 0U;
    char error[SIC_MAX_ERROR_LEN];
    uint32_t packet_id = 0U;
    int payload_length;
    int transform;
    int verdict;

    (void)message;
    ++context->stats.received;
    header = nfq_get_msg_packet_hdr(data);
    if (header != NULL) {
        packet_id = ntohl(header->packet_id);
    }
    payload_length = nfq_get_payload(data, &payload);
    if (header == NULL || payload_length < 0 || payload == NULL) {
        ++context->stats.dropped;
        sic_log(SIC_LOG_WARN, "queue %u: missing packet id or payload",
                context->queue_number);
        return nfq_set_verdict(queue, packet_id, NF_DROP, 0U, NULL);
    }

    if (context->mode == SIC_QUEUE_ENCRYPT) {
        transform = sic_packet_encrypt(context->session, payload,
                                       (size_t)payload_length, &output,
                                       &output_length, &counter,
                                       error, sizeof(error));
    } else {
        transform = sic_packet_decrypt(context->session, payload,
                                       (size_t)payload_length, &output,
                                       &output_length, &counter,
                                       error, sizeof(error));
    }

    if (transform == SIC_PACKET_MODIFIED) {
        ++context->stats.modified;
        sic_log(SIC_LOG_DEBUG, "queue %u: %s packet counter=%llu, %d -> %zu bytes",
                context->queue_number,
                context->mode == SIC_QUEUE_ENCRYPT ? "encrypted" : "decrypted",
                (unsigned long long)counter, payload_length, output_length);
        verdict = nfq_set_verdict(queue, packet_id, NF_ACCEPT,
                                  (uint32_t)output_length, output);
    } else if (transform == SIC_PACKET_PASS) {
        ++context->stats.passed;
        verdict = nfq_set_verdict(queue, packet_id, NF_ACCEPT, 0U, NULL);
    } else {
        ++context->stats.dropped;
        sic_log(SIC_LOG_WARN, "queue %u: dropping packet: %s",
                context->queue_number, error);
        verdict = nfq_set_verdict(queue, packet_id, NF_DROP, 0U, NULL);
    }
    if (output != NULL) {
        sic_secure_zero(output, output_length);
        free(output);
    }
    return verdict;
}

int sic_nfqueue_run(uint16_t encrypt_queue, uint16_t decrypt_queue,
                    struct sic_session *session,
                    volatile sig_atomic_t *stop,
                    struct sic_queue_stats *encrypt_stats,
                    struct sic_queue_stats *decrypt_stats,
                    char *error, size_t error_length)
{
    struct nfq_handle *handle = NULL;
    struct nfq_q_handle *encrypt_handle = NULL;
    struct nfq_q_handle *decrypt_handle = NULL;
    struct sic_queue_context encrypt_context;
    struct sic_queue_context decrypt_context;
    uint8_t *buffer = NULL;
    int fd;
    int receive_buffer = 4 * 1024 * 1024;
    int result = -1;

    (void)memset(&encrypt_context, 0, sizeof(encrypt_context));
    (void)memset(&decrypt_context, 0, sizeof(decrypt_context));
    encrypt_context.queue_number = encrypt_queue;
    encrypt_context.mode = SIC_QUEUE_ENCRYPT;
    encrypt_context.session = session;
    decrypt_context.queue_number = decrypt_queue;
    decrypt_context.mode = SIC_QUEUE_DECRYPT;
    decrypt_context.session = session;

    handle = nfq_open();
    if (handle == NULL) {
        sic_set_error(error, error_length, "nfq_open failed: %s",
                      strerror(errno));
        goto cleanup;
    }
    if (nfq_bind_pf(handle, AF_INET) < 0) {
        sic_set_error(error, error_length, "cannot bind NFQUEUE to IPv4: %s",
                      strerror(errno));
        goto cleanup;
    }
    encrypt_handle = nfq_create_queue(handle, encrypt_queue,
                                      packet_callback, &encrypt_context);
    decrypt_handle = nfq_create_queue(handle, decrypt_queue,
                                      packet_callback, &decrypt_context);
    if (encrypt_handle == NULL || decrypt_handle == NULL) {
        sic_set_error(error, error_length,
                      "cannot create NFQUEUE %u/%u (already in use?): %s",
                      encrypt_queue, decrypt_queue, strerror(errno));
        goto cleanup;
    }
    if (nfq_set_mode(encrypt_handle, NFQNL_COPY_PACKET, 0xffffU) < 0 ||
        nfq_set_mode(decrypt_handle, NFQNL_COPY_PACKET, 0xffffU) < 0 ||
        nfq_set_queue_maxlen(encrypt_handle, SIC_QUEUE_MAX_LENGTH) < 0 ||
        nfq_set_queue_maxlen(decrypt_handle, SIC_QUEUE_MAX_LENGTH) < 0) {
        sic_set_error(error, error_length, "cannot configure NFQUEUE: %s",
                      strerror(errno));
        goto cleanup;
    }

    fd = nfq_fd(handle);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer,
                     sizeof(receive_buffer));
    buffer = malloc(SIC_NETLINK_BUFFER_SIZE);
    if (buffer == NULL) {
        sic_set_error(error, error_length, "cannot allocate netlink buffer");
        goto cleanup;
    }

    sic_log(SIC_LOG_INFO,
            "packet processing active: encrypt queue=%u, decrypt queue=%u",
            encrypt_queue, decrypt_queue);
    result = 0;
    while (*stop == 0) {
        struct pollfd poll_descriptor;
        int poll_result;
        ssize_t received;

        poll_descriptor.fd = fd;
        poll_descriptor.events = POLLIN;
        poll_descriptor.revents = 0;
        poll_result = poll(&poll_descriptor, 1U, 500);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            sic_set_error(error, error_length, "NFQUEUE poll failed: %s",
                          strerror(errno));
            result = -1;
            break;
        }
        if (poll_result == 0) {
            continue;
        }
        if ((poll_descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            sic_set_error(error, error_length,
                          "NFQUEUE netlink socket reported an error");
            result = -1;
            break;
        }
        received = recv(fd, buffer, SIC_NETLINK_BUFFER_SIZE, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ENOBUFS) {
                sic_log(SIC_LOG_ERROR,
                        "NFQUEUE receive buffer overflow; packets were dropped");
                continue;
            }
            sic_set_error(error, error_length, "NFQUEUE receive failed: %s",
                          strerror(errno));
            result = -1;
            break;
        }
        if (nfq_handle_packet(handle, (char *)(void *)buffer,
                              (int)received) < 0) {
            sic_log(SIC_LOG_WARN, "invalid NFQUEUE netlink message ignored");
        }
    }

cleanup:
    if (encrypt_stats != NULL) {
        *encrypt_stats = encrypt_context.stats;
    }
    if (decrypt_stats != NULL) {
        *decrypt_stats = decrypt_context.stats;
    }
    free(buffer);
    if (decrypt_handle != NULL) {
        (void)nfq_destroy_queue(decrypt_handle);
    }
    if (encrypt_handle != NULL) {
        (void)nfq_destroy_queue(encrypt_handle);
    }
    if (handle != NULL) {
        (void)nfq_close(handle);
    }
    return result;
}
