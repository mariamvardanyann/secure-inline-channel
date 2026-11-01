#ifndef TEST_STUB_LIBNETFILTER_QUEUE_H
#define TEST_STUB_LIBNETFILTER_QUEUE_H

/*
 * Compile-only subset used by `make syntax-daemon` in minimal CI images.
 * The real daemon target never includes this directory and requires the
 * distribution's libnetfilter_queue development package.
 */

#include <stdint.h>

#define NFQNL_COPY_PACKET 2U

struct nfq_handle;
struct nfq_q_handle;
struct nfq_data;
struct nfgenmsg;

struct nfqnl_msg_packet_hdr {
    uint32_t packet_id;
    uint16_t hw_protocol;
    uint8_t hook;
} __attribute__((packed));

typedef int nfq_callback(struct nfq_q_handle *, struct nfgenmsg *,
                         struct nfq_data *, void *);

struct nfq_handle *nfq_open(void);
int nfq_close(struct nfq_handle *handle);
int nfq_bind_pf(struct nfq_handle *handle, uint16_t protocol_family);
struct nfq_q_handle *nfq_create_queue(struct nfq_handle *handle,
                                      uint16_t queue_number,
                                      nfq_callback *callback, void *data);
int nfq_destroy_queue(struct nfq_q_handle *queue);
int nfq_handle_packet(struct nfq_handle *handle, char *buffer, int length);
int nfq_fd(struct nfq_handle *handle);
int nfq_set_mode(struct nfq_q_handle *queue, uint8_t mode, uint32_t range);
int nfq_set_queue_maxlen(struct nfq_q_handle *queue, uint32_t length);
struct nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(struct nfq_data *data);
int nfq_get_payload(struct nfq_data *data, unsigned char **payload);
int nfq_set_verdict(struct nfq_q_handle *queue, uint32_t packet_id,
                    uint32_t verdict, uint32_t data_length,
                    const unsigned char *buffer);

#endif
