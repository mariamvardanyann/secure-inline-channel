#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "sic/config.h"
#include "sic/crypto.h"
#include "sic/handshake.h"
#include "sic/packet.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned int tests_run = 0U;
static unsigned int tests_failed = 0U;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                      \
            (void)fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__,   \
                          #condition);                                           \
            return -1;                                                          \
        }                                                                       \
    } while (0)

static void run_test(const char *name, int (*test)(void))
{
    int result;

    ++tests_run;
    result = test();
    if (result == 0) {
        (void)printf("[PASS] %s\n", name);
    } else {
        ++tests_failed;
        (void)printf("[FAIL] %s\n", name);
    }
}

static int test_nonce_layout(void)
{
    const uint8_t prefix[4] = {0x11U, 0x22U, 0x33U, 0x44U};
    const uint8_t expected[12] = {
        0x11U, 0x22U, 0x33U, 0x44U, 0x01U, 0x02U,
        0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U};
    uint8_t nonce[12];

    sic_make_nonce(prefix, UINT64_C(0x0102030405060708), nonce);
    CHECK(memcmp(nonce, expected, sizeof(nonce)) == 0);
    return 0;
}

static int test_nist_empty_gcm_vector(void)
{
    const uint8_t expected_tag[16] = {
        0x53U, 0x0fU, 0x8aU, 0xfbU, 0xc7U, 0x45U, 0x36U, 0xb9U,
        0xa9U, 0x63U, 0xb4U, 0xf1U, 0xc4U, 0xcbU, 0x73U, 0x8bU};
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t tag[16];
    uint8_t dummy = 0U;
    char error[128];

    CHECK(sic_aes_gcm_encrypt(key, nonce, NULL, 0U, NULL, 0U,
                              &dummy, tag, error, sizeof(error)) == 0);
    CHECK(memcmp(tag, expected_tag, sizeof(tag)) == 0);
    CHECK(sic_aes_gcm_decrypt(key, nonce, NULL, 0U, NULL, 0U,
                              tag, &dummy) == 0);
    return 0;
}

static int test_gcm_tamper_detection(void)
{
    const uint8_t plaintext[] = "authenticated message";
    const uint8_t aad[] = "stable headers";
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t recovered[sizeof(plaintext)];
    uint8_t tag[16];
    char error[128];

    (void)memset(key, 0x5a, sizeof(key));
    (void)memset(nonce, 0xa5, sizeof(nonce));
    CHECK(sic_aes_gcm_encrypt(key, nonce, aad, sizeof(aad),
                              plaintext, sizeof(plaintext), ciphertext, tag,
                              error, sizeof(error)) == 0);
    CHECK(sic_aes_gcm_decrypt(key, nonce, aad, sizeof(aad), ciphertext,
                              sizeof(ciphertext), tag, recovered) == 0);
    CHECK(memcmp(recovered, plaintext, sizeof(plaintext)) == 0);
    ciphertext[2] ^= 0x01U;
    CHECK(sic_aes_gcm_decrypt(key, nonce, aad, sizeof(aad), ciphertext,
                              sizeof(ciphertext), tag, recovered) != 0);
    ciphertext[2] ^= 0x01U;
    tag[0] ^= 0x80U;
    CHECK(sic_aes_gcm_decrypt(key, nonce, aad, sizeof(aad), ciphertext,
                              sizeof(ciphertext), tag, recovered) != 0);
    return 0;
}

static uint8_t *build_packet(const uint8_t *payload, size_t payload_length,
                             uint32_t sequence, size_t *packet_length)
{
    size_t length = sizeof(struct iphdr) + sizeof(struct tcphdr) +
                    payload_length;
    uint8_t *packet = calloc(1U, length);
    struct iphdr *ip;
    struct tcphdr *tcp;

    if (packet == NULL || length > UINT16_MAX) {
        free(packet);
        return NULL;
    }
    ip = (struct iphdr *)(void *)packet;
    tcp = (struct tcphdr *)(void *)(packet + sizeof(struct iphdr));
    ip->version = 4U;
    ip->ihl = 5U;
    ip->tos = 0x10U;
    ip->tot_len = htons((uint16_t)length);
    ip->id = htons(0x1234U);
    ip->frag_off = htons(0x4000U);
    ip->ttl = 63U;
    ip->protocol = IPPROTO_TCP;
    (void)inet_pton(AF_INET, "10.0.1.2", &ip->saddr);
    (void)inet_pton(AF_INET, "10.0.2.2", &ip->daddr);
    tcp->source = htons(50123U);
    tcp->dest = htons(8080U);
    tcp->seq = htonl(sequence);
    tcp->ack_seq = htonl(77U);
    tcp->doff = 5U;
    tcp->ack = 1U;
    tcp->psh = 1U;
    tcp->window = htons(64240U);
    if (payload_length > 0U) {
        (void)memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr),
                     payload, payload_length);
    }
    ip->check = sic_ipv4_checksum(packet, sizeof(struct iphdr));
    tcp->check = sic_tcp_checksum(packet, length);
    *packet_length = length;
    return packet;
}

static int init_session_pair(struct sic_session *first,
                             struct sic_session *second)
{
    uint8_t key_ab[32];
    uint8_t key_ba[32];
    uint8_t prefix_ab[4] = {1U, 2U, 3U, 4U};
    uint8_t prefix_ba[4] = {5U, 6U, 7U, 8U};
    uint8_t session_id[16];
    char error[128];

    (void)memset(key_ab, 0x11, sizeof(key_ab));
    (void)memset(key_ba, 0x22, sizeof(key_ba));
    (void)memset(session_id, 0x33, sizeof(session_id));
    if (sic_session_init(first, key_ab, key_ba, prefix_ab, prefix_ba,
                         session_id, 64U, 64U, error, sizeof(error)) != 0) {
        return -1;
    }
    if (sic_session_init(second, key_ba, key_ab, prefix_ba, prefix_ab,
                         session_id, 64U, 64U, error, sizeof(error)) != 0) {
        sic_session_clear(first);
        return -1;
    }
    return 0;
}

static int test_packet_round_trip(void)
{
    const uint8_t payload[] = "GET /secret HTTP/1.1\r\n\r\n";
    struct sic_session sender;
    struct sic_session receiver;
    uint8_t *plain;
    uint8_t *encrypted = NULL;
    uint8_t *decrypted = NULL;
    size_t plain_length;
    size_t encrypted_length = 0U;
    size_t decrypted_length = 0U;
    uint64_t send_counter = UINT64_MAX;
    uint64_t receive_counter = UINT64_MAX;
    char error[256];

    (void)memset(&sender, 0, sizeof(sender));
    (void)memset(&receiver, 0, sizeof(receiver));
    CHECK(init_session_pair(&sender, &receiver) == 0);
    plain = build_packet(payload, sizeof(payload), 1000U, &plain_length);
    CHECK(plain != NULL);
    CHECK(sic_packet_checksums_valid(plain, plain_length) != 0);
    CHECK(sic_packet_encrypt(&sender, plain, plain_length, &encrypted,
                             &encrypted_length, &send_counter,
                             error, sizeof(error)) == SIC_PACKET_MODIFIED);
    CHECK(send_counter == 0U);
    CHECK(encrypted_length == plain_length + SIC_GCM_TAG_LEN);
    CHECK(sic_packet_checksums_valid(encrypted, encrypted_length) != 0);
    CHECK(memcmp(encrypted + sizeof(struct iphdr) + sizeof(struct tcphdr),
                 payload, sizeof(payload)) != 0);
    CHECK(sic_packet_decrypt(&receiver, encrypted, encrypted_length,
                             &decrypted, &decrypted_length, &receive_counter,
                             error, sizeof(error)) == SIC_PACKET_MODIFIED);
    CHECK(receive_counter == 0U);
    CHECK(decrypted_length == plain_length);
    CHECK(memcmp(decrypted, plain, plain_length) == 0);
    CHECK(sic_packet_checksums_valid(decrypted, decrypted_length) != 0);

    free(plain);
    free(encrypted);
    free(decrypted);
    sic_session_clear(&sender);
    sic_session_clear(&receiver);
    return 0;
}

static int test_payloadless_packet_passes(void)
{
    struct sic_session sender;
    struct sic_session receiver;
    uint8_t *packet;
    uint8_t *output = NULL;
    size_t packet_length;
    size_t output_length = 99U;
    char error[128];

    (void)memset(&sender, 0, sizeof(sender));
    (void)memset(&receiver, 0, sizeof(receiver));
    CHECK(init_session_pair(&sender, &receiver) == 0);
    packet = build_packet(NULL, 0U, 1234U, &packet_length);
    CHECK(packet != NULL);
    CHECK(sic_packet_encrypt(&sender, packet, packet_length,
                             &output, &output_length, NULL,
                             error, sizeof(error)) == SIC_PACKET_PASS);
    CHECK(output == NULL);
    CHECK(output_length == 0U);
    CHECK(sic_packet_decrypt(&receiver, packet, packet_length,
                             &output, &output_length, NULL,
                             error, sizeof(error)) == SIC_PACKET_PASS);
    free(packet);
    sic_session_clear(&sender);
    sic_session_clear(&receiver);
    return 0;
}

static int test_retransmission_gets_fresh_nonce(void)
{
    const uint8_t aad[] = "same header";
    const uint8_t plaintext[] = "same retransmitted payload";
    struct sic_session sender;
    struct sic_session receiver;
    uint8_t ciphertext1[sizeof(plaintext)];
    uint8_t ciphertext2[sizeof(plaintext)];
    uint8_t recovered[sizeof(plaintext)];
    uint8_t tag1[16];
    uint8_t tag2[16];
    uint64_t counter1 = UINT64_MAX;
    uint64_t counter2 = UINT64_MAX;
    char error[128];

    (void)memset(&sender, 0, sizeof(sender));
    (void)memset(&receiver, 0, sizeof(receiver));
    CHECK(init_session_pair(&sender, &receiver) == 0);
    CHECK(sic_session_encrypt(&sender, aad, sizeof(aad),
                              plaintext, sizeof(plaintext), ciphertext1, tag1,
                              &counter1, error, sizeof(error)) == 0);
    CHECK(sic_session_encrypt(&sender, aad, sizeof(aad),
                              plaintext, sizeof(plaintext), ciphertext2, tag2,
                              &counter2, error, sizeof(error)) == 0);
    CHECK(counter1 == 0U);
    CHECK(counter2 == 1U);
    CHECK(memcmp(ciphertext1, ciphertext2, sizeof(ciphertext1)) != 0);
    CHECK(memcmp(tag1, tag2, sizeof(tag1)) != 0);
    CHECK(sic_session_decrypt(&receiver, aad, sizeof(aad), ciphertext1,
                              sizeof(ciphertext1), tag1, recovered, NULL,
                              error, sizeof(error)) == 0);
    CHECK(sic_session_decrypt(&receiver, aad, sizeof(aad), ciphertext2,
                              sizeof(ciphertext2), tag2, recovered, NULL,
                              error, sizeof(error)) == 0);
    sic_session_clear(&sender);
    sic_session_clear(&receiver);
    return 0;
}

static int test_fragment_rejected(void)
{
    const uint8_t payload[] = "fragment";
    struct sic_session sender;
    struct sic_session receiver;
    uint8_t *packet;
    uint8_t *output = NULL;
    size_t packet_length;
    size_t output_length = 0U;
    char error[128];

    (void)memset(&sender, 0, sizeof(sender));
    (void)memset(&receiver, 0, sizeof(receiver));
    CHECK(init_session_pair(&sender, &receiver) == 0);
    packet = build_packet(payload, sizeof(payload), 1500U, &packet_length);
    CHECK(packet != NULL);
    ((struct iphdr *)(void *)packet)->frag_off = htons(0x2000U);
    CHECK(sic_packet_encrypt(&sender, packet, packet_length,
                             &output, &output_length, NULL,
                             error, sizeof(error)) == SIC_PACKET_ERROR);
    CHECK(strstr(error, "fragmented") != NULL);
    CHECK(output == NULL);
    free(packet);
    sic_session_clear(&sender);
    sic_session_clear(&receiver);
    return 0;
}

static int test_reordering_and_replay(void)
{
    const uint8_t payloads[3][8] = {"packet0", "packet1", "packet2"};
    struct sic_session sender;
    struct sic_session receiver;
    uint8_t *wire[3] = {NULL, NULL, NULL};
    size_t wire_length[3] = {0U, 0U, 0U};
    size_t index;
    const size_t order[3] = {1U, 0U, 2U};
    char error[256];

    (void)memset(&sender, 0, sizeof(sender));
    (void)memset(&receiver, 0, sizeof(receiver));
    CHECK(init_session_pair(&sender, &receiver) == 0);
    for (index = 0U; index < 3U; ++index) {
        uint8_t *plain;
        size_t plain_length;
        plain = build_packet(payloads[index], sizeof(payloads[index]),
                             2000U + (uint32_t)(index * 8U), &plain_length);
        CHECK(plain != NULL);
        CHECK(sic_packet_encrypt(&sender, plain, plain_length, &wire[index],
                                 &wire_length[index], NULL,
                                 error, sizeof(error)) == SIC_PACKET_MODIFIED);
        free(plain);
    }
    for (index = 0U; index < 3U; ++index) {
        uint8_t *plain = NULL;
        size_t plain_length = 0U;
        uint64_t counter = UINT64_MAX;
        size_t selected = order[index];
        CHECK(sic_packet_decrypt(&receiver, wire[selected],
                                 wire_length[selected], &plain, &plain_length,
                                 &counter, error,
                                 sizeof(error)) == SIC_PACKET_MODIFIED);
        CHECK(counter == selected);
        free(plain);
    }
    {
        uint8_t *plain = NULL;
        size_t plain_length = 0U;
        CHECK(sic_packet_decrypt(&receiver, wire[0], wire_length[0],
                                 &plain, &plain_length, NULL,
                                 error, sizeof(error)) == SIC_PACKET_ERROR);
        CHECK(plain == NULL);
    }
    for (index = 0U; index < 3U; ++index) {
        free(wire[index]);
    }
    sic_session_clear(&sender);
    sic_session_clear(&receiver);
    return 0;
}

static int test_header_tamper_detection(void)
{
    const uint8_t payload[] = "top secret";
    struct sic_session sender;
    struct sic_session receiver;
    uint8_t *plain;
    uint8_t *wire = NULL;
    uint8_t *output = NULL;
    size_t plain_length;
    size_t wire_length = 0U;
    size_t output_length = 0U;
    char error[256];

    (void)memset(&sender, 0, sizeof(sender));
    (void)memset(&receiver, 0, sizeof(receiver));
    CHECK(init_session_pair(&sender, &receiver) == 0);
    plain = build_packet(payload, sizeof(payload), 3000U, &plain_length);
    CHECK(plain != NULL);
    CHECK(sic_packet_encrypt(&sender, plain, plain_length, &wire, &wire_length,
                             NULL, error, sizeof(error)) == SIC_PACKET_MODIFIED);
    ((struct tcphdr *)(void *)(wire + sizeof(struct iphdr)))->dest =
        htons(8081U);
    CHECK(sic_packet_decrypt(&receiver, wire, wire_length,
                             &output, &output_length, NULL,
                             error, sizeof(error)) == SIC_PACKET_ERROR);
    CHECK(output == NULL);
    free(plain);
    free(wire);
    sic_session_clear(&sender);
    sic_session_clear(&receiver);
    return 0;
}

struct handshake_thread_args {
    int fd;
    struct sic_config config;
    struct sic_session session;
    int result;
    char error[256];
};

static void *handshake_thread(void *argument)
{
    struct handshake_thread_args *args = argument;

    args->result = sic_handshake_over_fd(args->fd, &args->config,
                                         &args->session, args->error,
                                         sizeof(args->error));
    (void)shutdown(args->fd, SHUT_RDWR);
    (void)close(args->fd);
    return NULL;
}

static int test_diffie_hellman_handshake(void)
{
    struct handshake_thread_args client;
    struct handshake_thread_args server;
    int sockets[2];
    pthread_t client_thread;
    pthread_t server_thread;
    size_t index;

    (void)memset(&client, 0, sizeof(client));
    (void)memset(&server, 0, sizeof(server));
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    sic_config_defaults(&client.config);
    sic_config_defaults(&server.config);
    client.config.role = SIC_ROLE_DEVICE1;
    server.config.role = SIC_ROLE_DEVICE2;
    client.fd = sockets[0];
    server.fd = sockets[1];
    client.config.psk_length = 32U;
    server.config.psk_length = 32U;
    for (index = 0U; index < 32U; ++index) {
        client.config.psk[index] = (uint8_t)index;
        server.config.psk[index] = (uint8_t)index;
    }
    CHECK(pthread_create(&server_thread, NULL, handshake_thread, &server) == 0);
    CHECK(pthread_create(&client_thread, NULL, handshake_thread, &client) == 0);
    CHECK(pthread_join(client_thread, NULL) == 0);
    CHECK(pthread_join(server_thread, NULL) == 0);
    if (client.result != 0) {
        (void)fprintf(stderr, "client handshake: %s\n", client.error);
    }
    if (server.result != 0) {
        (void)fprintf(stderr, "server handshake: %s\n", server.error);
    }
    CHECK(client.result == 0);
    CHECK(server.result == 0);
    CHECK(memcmp(client.session.tx_key, server.session.rx_key, 32U) == 0);
    CHECK(memcmp(client.session.rx_key, server.session.tx_key, 32U) == 0);
    CHECK(memcmp(client.session.tx_nonce_prefix,
                 server.session.rx_nonce_prefix, 4U) == 0);
    CHECK(memcmp(client.session.session_id,
                 server.session.session_id, 16U) == 0);
    sic_session_clear(&client.session);
    sic_session_clear(&server.session);
    sic_config_clear(&client.config);
    sic_config_clear(&server.config);
    return 0;
}

static int test_mismatched_psk_rejected(void)
{
    struct handshake_thread_args client;
    struct handshake_thread_args server;
    int sockets[2];
    pthread_t client_thread;
    pthread_t server_thread;

    (void)memset(&client, 0, sizeof(client));
    (void)memset(&server, 0, sizeof(server));
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    sic_config_defaults(&client.config);
    sic_config_defaults(&server.config);
    client.config.role = SIC_ROLE_DEVICE1;
    server.config.role = SIC_ROLE_DEVICE2;
    client.config.psk_length = 32U;
    server.config.psk_length = 32U;
    (void)memset(client.config.psk, 0x41, 32U);
    (void)memset(server.config.psk, 0x42, 32U);
    client.fd = sockets[0];
    server.fd = sockets[1];
    CHECK(pthread_create(&server_thread, NULL, handshake_thread, &server) == 0);
    CHECK(pthread_create(&client_thread, NULL, handshake_thread, &client) == 0);
    CHECK(pthread_join(client_thread, NULL) == 0);
    CHECK(pthread_join(server_thread, NULL) == 0);
    CHECK(client.result != 0);
    CHECK(server.result != 0);
    CHECK(client.session.initialized == 0);
    CHECK(server.session.initialized == 0);
    sic_config_clear(&client.config);
    sic_config_clear(&server.config);
    return 0;
}

static int test_config_parser(void)
{
    static const char contents[] =
        "role=device1\n"
        "peer_address=10.0.12.2\n"
        "control_port=48000\n"
        "encrypt_queue=200\n"
        "decrypt_queue=201\n"
        "replay_window=256\n"
        "counter_lookahead=64\n"
        "log_level=debug\n"
        "psk_hex=000102030405060708090a0b0c0d0e0f\n";
    char path[] = "/tmp/sic-config-test-XXXXXX";
    struct sic_config config;
    char error[256];
    int fd;
    ssize_t written;

    (void)memset(&config, 0, sizeof(config));
    fd = mkstemp(path);
    CHECK(fd >= 0);
    written = write(fd, contents, sizeof(contents) - 1U);
    CHECK(written == (ssize_t)(sizeof(contents) - 1U));
    CHECK(close(fd) == 0);
    CHECK(sic_config_load(path, &config, error, sizeof(error)) == 0);
    CHECK(unlink(path) == 0);
    CHECK(config.role == SIC_ROLE_DEVICE1);
    CHECK(strcmp(config.peer_address, "10.0.12.2") == 0);
    CHECK(config.control_port == 48000U);
    CHECK(config.encrypt_queue == 200U);
    CHECK(config.decrypt_queue == 201U);
    CHECK(config.replay_window == 256U);
    CHECK(config.counter_lookahead == 64U);
    CHECK(config.log_level == SIC_LOG_DEBUG);
    CHECK(config.psk_length == 16U);
    sic_config_clear(&config);
    return 0;
}

int main(void)
{
    sic_set_log_level(SIC_LOG_ERROR);
    run_test("96-bit nonce layout and counter", test_nonce_layout);
    run_test("NIST AES-256-GCM empty-message vector",
             test_nist_empty_gcm_vector);
    run_test("AES-GCM rejects ciphertext/tag tampering",
             test_gcm_tamper_detection);
    run_test("TCP/IPv4 encrypt-decrypt round trip", test_packet_round_trip);
    run_test("payloadless TCP control packet passes unchanged",
             test_payloadless_packet_passes);
    run_test("retransmission receives a fresh counter and nonce",
             test_retransmission_gets_fresh_nonce);
    run_test("fragmented IPv4 packet is rejected", test_fragment_rejected);
    run_test("out-of-order acceptance and replay rejection",
             test_reordering_and_replay);
    run_test("authenticated TCP header rejects tampering",
             test_header_tamper_detection);
    run_test("FFDHE2048 handshake derives matching directional keys",
             test_diffie_hellman_handshake);
    run_test("mismatched handshake PSKs are rejected",
             test_mismatched_psk_rejected);
    run_test("strict key-value configuration parser", test_config_parser);

    (void)printf("\n%u tests, %u failures\n", tests_run, tests_failed);
    return tests_failed == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
