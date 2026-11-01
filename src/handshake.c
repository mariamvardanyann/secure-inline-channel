#define _POSIX_C_SOURCE 200809L

#include "sic/handshake.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rand.h>

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define SIC_HELLO_HEADER_LEN 44U
#define SIC_MAX_PUBLIC_KEY_LEN 4096U
#define SIC_KEY_MATERIAL_LEN 104U
#define SIC_FINISHED_LEN 32U

struct sic_hello {
    uint8_t random[SIC_RANDOM_LEN];
    uint8_t *wire;
    size_t wire_length;
    EVP_PKEY *public_key;
};

static void set_openssl_error(char *error, size_t error_length,
                              const char *operation)
{
    unsigned long code = ERR_peek_last_error();
    char detail[160];

    if (code == 0UL) {
        sic_set_error(error, error_length, "%s failed", operation);
        return;
    }
    ERR_error_string_n(code, detail, sizeof(detail));
    sic_set_error(error, error_length, "%s failed: %s", operation, detail);
}

static uint32_t load_u32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24U) | ((uint32_t)data[1] << 16U) |
           ((uint32_t)data[2] << 8U) | data[3];
}

static void store_u32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24U);
    data[1] = (uint8_t)(value >> 16U);
    data[2] = (uint8_t)(value >> 8U);
    data[3] = (uint8_t)value;
}

static int write_all(int fd, const uint8_t *data, size_t length)
{
    size_t written = 0U;

    while (written < length) {
        ssize_t count = send(fd, data + written, length - written, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return -1;
        }
        written += (size_t)count;
    }
    return 0;
}

static int read_all(int fd, uint8_t *data, size_t length)
{
    size_t received = 0U;

    while (received < length) {
        ssize_t count = recv(fd, data + received, length - received, 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return -1;
        }
        received += (size_t)count;
    }
    return 0;
}

static EVP_PKEY *generate_dh_key(char *error, size_t error_length)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    EVP_PKEY *key = NULL;

    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_CTX_set_group_name(context, "ffdhe2048") <= 0 ||
        EVP_PKEY_generate(context, &key) <= 0) {
        set_openssl_error(error, error_length, "FFDHE2048 key generation");
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int build_hello(enum sic_role role, EVP_PKEY *key,
                       struct sic_hello *hello,
                       char *error, size_t error_length)
{
    int encoded_length;
    unsigned char *cursor;

    (void)memset(hello, 0, sizeof(*hello));
    if (RAND_bytes_ex(NULL, hello->random, sizeof(hello->random), 0U) != 1) {
        set_openssl_error(error, error_length, "random generation");
        return -1;
    }
    encoded_length = i2d_PUBKEY(key, NULL);
    if (encoded_length <= 0 ||
        (unsigned int)encoded_length > SIC_MAX_PUBLIC_KEY_LEN) {
        sic_set_error(error, error_length,
                      "cannot encode FFDHE2048 public key");
        return -1;
    }
    hello->wire_length = SIC_HELLO_HEADER_LEN + (size_t)encoded_length;
    hello->wire = calloc(hello->wire_length, 1U);
    if (hello->wire == NULL) {
        sic_set_error(error, error_length, "cannot allocate handshake hello");
        return -1;
    }
    (void)memcpy(hello->wire, "SIC1", 4U);
    hello->wire[4] = SIC_VERSION;
    hello->wire[5] = (uint8_t)role;
    (void)memcpy(hello->wire + 8U, hello->random, SIC_RANDOM_LEN);
    store_u32(hello->wire + 40U, (uint32_t)encoded_length);
    cursor = hello->wire + SIC_HELLO_HEADER_LEN;
    if (i2d_PUBKEY(key, &cursor) != encoded_length) {
        sic_set_error(error, error_length,
                      "inconsistent public-key encoding length");
        free(hello->wire);
        hello->wire = NULL;
        return -1;
    }
    hello->public_key = key;
    return 0;
}

static int validate_public_key(EVP_PKEY *key,
                               char *error, size_t error_length)
{
    EVP_PKEY_CTX *context = NULL;
    char group[80];
    size_t group_length = 0U;
    int result = -1;

    if (key == NULL || EVP_PKEY_is_a(key, "DH") != 1 ||
        EVP_PKEY_get_bits(key) < 2048 ||
        EVP_PKEY_get_group_name(key, group, sizeof(group),
                                &group_length) != 1 ||
        strcmp(group, "ffdhe2048") != 0) {
        sic_set_error(error, error_length,
                      "peer key is not a valid ffdhe2048 DH key");
        return -1;
    }
    context = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (context != NULL && EVP_PKEY_public_check(context) == 1) {
        result = 0;
    } else {
        set_openssl_error(error, error_length, "peer DH public-key validation");
    }
    EVP_PKEY_CTX_free(context);
    return result;
}

static int receive_hello(int fd, enum sic_role expected_role,
                         struct sic_hello *hello,
                         char *error, size_t error_length)
{
    uint8_t header[SIC_HELLO_HEADER_LEN];
    uint32_t public_length;
    const unsigned char *cursor;

    (void)memset(hello, 0, sizeof(*hello));
    if (read_all(fd, header, sizeof(header)) != 0) {
        sic_set_error(error, error_length, "cannot receive handshake hello: %s",
                      strerror(errno));
        return -1;
    }
    public_length = load_u32(header + 40U);
    if (memcmp(header, "SIC1", 4U) != 0 || header[4] != SIC_VERSION ||
        header[5] != (uint8_t)expected_role || header[6] != 0U ||
        header[7] != 0U || public_length == 0U ||
        public_length > SIC_MAX_PUBLIC_KEY_LEN) {
        sic_set_error(error, error_length, "invalid handshake hello");
        return -1;
    }
    hello->wire_length = SIC_HELLO_HEADER_LEN + public_length;
    hello->wire = malloc(hello->wire_length);
    if (hello->wire == NULL) {
        sic_set_error(error, error_length, "cannot allocate peer hello");
        return -1;
    }
    (void)memcpy(hello->wire, header, sizeof(header));
    if (read_all(fd, hello->wire + SIC_HELLO_HEADER_LEN, public_length) != 0) {
        sic_set_error(error, error_length,
                      "cannot receive peer public key: %s", strerror(errno));
        return -1;
    }
    (void)memcpy(hello->random, header + 8U, SIC_RANDOM_LEN);
    cursor = hello->wire + SIC_HELLO_HEADER_LEN;
    hello->public_key = d2i_PUBKEY(NULL, &cursor, (long)public_length);
    if (hello->public_key == NULL) {
        set_openssl_error(error, error_length, "peer public-key decoding");
        return -1;
    }
    if (cursor != hello->wire + hello->wire_length ||
        validate_public_key(hello->public_key, error, error_length) != 0) {
        return -1;
    }
    return 0;
}

static void free_hello(struct sic_hello *hello, int owns_key)
{
    if (hello == NULL) {
        return;
    }
    if (owns_key != 0) {
        EVP_PKEY_free(hello->public_key);
    }
    free(hello->wire);
    (void)memset(hello, 0, sizeof(*hello));
}

static int sha256_parts(const uint8_t *first, size_t first_length,
                        const uint8_t *second, size_t second_length,
                        const uint8_t *third, size_t third_length,
                        uint8_t output[32])
{
    EVP_MD_CTX *context = NULL;
    EVP_MD *digest = EVP_MD_fetch(NULL, "SHA256", NULL);
    unsigned int output_length = 0U;
    int result = -1;

    context = EVP_MD_CTX_new();
    if (digest == NULL || context == NULL ||
        EVP_DigestInit_ex2(context, digest, NULL) != 1 ||
        (first_length > 0U &&
         EVP_DigestUpdate(context, first, first_length) != 1) ||
        (second_length > 0U &&
         EVP_DigestUpdate(context, second, second_length) != 1) ||
        (third_length > 0U &&
         EVP_DigestUpdate(context, third, third_length) != 1) ||
        EVP_DigestFinal_ex(context, output, &output_length) != 1 ||
        output_length != 32U) {
        goto cleanup;
    }
    result = 0;

cleanup:
    EVP_MD_CTX_free(context);
    EVP_MD_free(digest);
    return result;
}

static int derive_secret(EVP_PKEY *local_key, EVP_PKEY *peer_key,
                         uint8_t **secret, size_t *secret_length,
                         char *error, size_t error_length)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_pkey(NULL, local_key, NULL);
    int result = -1;

    if (context == NULL || EVP_PKEY_derive_init(context) <= 0 ||
        EVP_PKEY_derive_set_peer(context, peer_key) <= 0 ||
        EVP_PKEY_derive(context, NULL, secret_length) <= 0) {
        set_openssl_error(error, error_length, "Diffie-Hellman derivation");
        goto cleanup;
    }
    *secret = OPENSSL_malloc(*secret_length);
    if (*secret == NULL ||
        EVP_PKEY_derive(context, *secret, secret_length) <= 0) {
        set_openssl_error(error, error_length, "Diffie-Hellman derivation");
        OPENSSL_clear_free(*secret, *secret_length);
        *secret = NULL;
        goto cleanup;
    }
    result = 0;

cleanup:
    EVP_PKEY_CTX_free(context);
    return result;
}

static int hkdf_schedule(const uint8_t *secret, size_t secret_length,
                         const uint8_t salt[32],
                         const uint8_t transcript_hash[32],
                         uint8_t material[SIC_KEY_MATERIAL_LEN],
                         char *error, size_t error_length)
{
    static const uint8_t label[] = "SIC-v1 key schedule";
    uint8_t info[sizeof(label) - 1U + 32U];
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *context = NULL;
    OSSL_PARAM params[5];
    size_t index = 0U;
    int result = -1;

    if (kdf != NULL) {
        context = EVP_KDF_CTX_new(kdf);
    }
    (void)memcpy(info, label, sizeof(label) - 1U);
    (void)memcpy(info + sizeof(label) - 1U, transcript_hash, 32U);
    params[index++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0U);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, (void *)secret, secret_length);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, (void *)salt, 32U);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, info, sizeof(info));
    params[index] = OSSL_PARAM_construct_end();

    if (kdf == NULL || context == NULL ||
        EVP_KDF_derive(context, material, SIC_KEY_MATERIAL_LEN, params) != 1) {
        set_openssl_error(error, error_length, "HKDF-SHA256 key schedule");
        goto cleanup;
    }
    result = 0;

cleanup:
    EVP_KDF_CTX_free(context);
    EVP_KDF_free(kdf);
    sic_secure_zero(info, sizeof(info));
    return result;
}

static int hmac_finished(const uint8_t key[32], const char *label,
                         const uint8_t transcript_hash[32],
                         uint8_t output[32],
                         char *error, size_t error_length)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *context = NULL;
    OSSL_PARAM params[2];
    size_t output_length = 0U;
    int result = -1;

    if (mac != NULL) {
        context = EVP_MAC_CTX_new(mac);
    }
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0U);
    params[1] = OSSL_PARAM_construct_end();
    if (mac == NULL || context == NULL ||
        EVP_MAC_init(context, key, 32U, params) != 1 ||
        EVP_MAC_update(context, (const uint8_t *)label, strlen(label)) != 1 ||
        EVP_MAC_update(context, transcript_hash, 32U) != 1 ||
        EVP_MAC_final(context, output, &output_length, 32U) != 1 ||
        output_length != 32U) {
        set_openssl_error(error, error_length, "handshake HMAC");
        goto cleanup;
    }
    result = 0;

cleanup:
    EVP_MAC_CTX_free(context);
    EVP_MAC_free(mac);
    return result;
}

int sic_handshake_over_fd(int fd, const struct sic_config *config,
                          struct sic_session *session,
                          char *error, size_t error_length)
{
    EVP_PKEY *local_key = NULL;
    struct sic_hello local_hello;
    struct sic_hello peer_hello;
    const struct sic_hello *client_hello;
    const struct sic_hello *server_hello;
    uint8_t *secret = NULL;
    size_t secret_length = 0U;
    uint8_t transcript_hash[32] = {0};
    uint8_t salt[32] = {0};
    uint8_t material[SIC_KEY_MATERIAL_LEN] = {0};
    uint8_t local_finished[SIC_FINISHED_LEN] = {0};
    uint8_t expected_finished[SIC_FINISHED_LEN] = {0};
    uint8_t received_finished[SIC_FINISHED_LEN] = {0};
    const uint8_t *tx_key;
    const uint8_t *rx_key;
    const uint8_t *tx_prefix;
    const uint8_t *rx_prefix;
    int result = -1;

    (void)memset(&local_hello, 0, sizeof(local_hello));
    (void)memset(&peer_hello, 0, sizeof(peer_hello));
    if (error != NULL && error_length > 0U) {
        error[0] = '\0';
    }
    local_key = generate_dh_key(error, error_length);
    if (local_key == NULL ||
        build_hello(config->role, local_key, &local_hello,
                    error, error_length) != 0) {
        goto cleanup;
    }

    if (config->role == SIC_ROLE_DEVICE1) {
        if (write_all(fd, local_hello.wire, local_hello.wire_length) != 0 ||
            receive_hello(fd, SIC_ROLE_DEVICE2, &peer_hello,
                          error, error_length) != 0) {
            if (error != NULL && error[0] == '\0') {
                sic_set_error(error, error_length,
                              "handshake hello exchange failed: %s",
                              strerror(errno));
            }
            goto cleanup;
        }
        client_hello = &local_hello;
        server_hello = &peer_hello;
    } else {
        if (receive_hello(fd, SIC_ROLE_DEVICE1, &peer_hello,
                          error, error_length) != 0 ||
            write_all(fd, local_hello.wire, local_hello.wire_length) != 0) {
            if (error != NULL && error[0] == '\0') {
                sic_set_error(error, error_length,
                              "handshake hello exchange failed: %s",
                              strerror(errno));
            }
            goto cleanup;
        }
        client_hello = &peer_hello;
        server_hello = &local_hello;
    }

    if (sha256_parts(client_hello->wire, client_hello->wire_length,
                     server_hello->wire, server_hello->wire_length,
                     NULL, 0U, transcript_hash) != 0 ||
        sha256_parts(client_hello->random, SIC_RANDOM_LEN,
                     server_hello->random, SIC_RANDOM_LEN,
                     config->psk, config->psk_length, salt) != 0) {
        set_openssl_error(error, error_length, "handshake hashing");
        goto cleanup;
    }
    if (derive_secret(local_key, peer_hello.public_key, &secret,
                      &secret_length, error, error_length) != 0 ||
        hkdf_schedule(secret, secret_length, salt, transcript_hash, material,
                      error, error_length) != 0 ||
        hmac_finished(material + 72U, "client finished", transcript_hash,
                      config->role == SIC_ROLE_DEVICE1 ? local_finished
                                                       : expected_finished,
                      error, error_length) != 0 ||
        hmac_finished(material + 72U, "server finished", transcript_hash,
                      config->role == SIC_ROLE_DEVICE2 ? local_finished
                                                       : expected_finished,
                      error, error_length) != 0) {
        goto cleanup;
    }

    if (config->role == SIC_ROLE_DEVICE1) {
        if (write_all(fd, local_finished, sizeof(local_finished)) != 0 ||
            read_all(fd, received_finished, sizeof(received_finished)) != 0) {
            sic_set_error(error, error_length,
                          "handshake finished exchange failed: %s",
                          strerror(errno));
            goto cleanup;
        }
    } else {
        if (read_all(fd, received_finished, sizeof(received_finished)) != 0 ||
            CRYPTO_memcmp(received_finished, expected_finished,
                          sizeof(received_finished)) != 0 ||
            write_all(fd, local_finished, sizeof(local_finished)) != 0) {
            sic_set_error(error, error_length,
                          "client handshake authentication failed");
            goto cleanup;
        }
    }
    if (config->role == SIC_ROLE_DEVICE1 &&
        CRYPTO_memcmp(received_finished, expected_finished,
                      sizeof(received_finished)) != 0) {
        sic_set_error(error, error_length,
                      "server handshake authentication failed");
        goto cleanup;
    }

    if (config->role == SIC_ROLE_DEVICE1) {
        tx_key = material;
        rx_key = material + 32U;
        tx_prefix = material + 64U;
        rx_prefix = material + 68U;
    } else {
        tx_key = material + 32U;
        rx_key = material;
        tx_prefix = material + 68U;
        rx_prefix = material + 64U;
    }
    if (sic_session_init(session, tx_key, rx_key, tx_prefix, rx_prefix,
                         transcript_hash, config->replay_window,
                         config->counter_lookahead,
                         error, error_length) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (secret != NULL) {
        OPENSSL_clear_free(secret, secret_length);
    }
    sic_secure_zero(material, sizeof(material));
    sic_secure_zero(local_finished, sizeof(local_finished));
    sic_secure_zero(expected_finished, sizeof(expected_finished));
    sic_secure_zero(received_finished, sizeof(received_finished));
    sic_secure_zero(salt, sizeof(salt));
    EVP_PKEY_free(local_key);
    free_hello(&local_hello, 0);
    free_hello(&peer_hello, 1);
    return result;
}

static void set_socket_timeouts(int fd)
{
    struct timeval timeout;
    int enabled = 1;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
}

static int connect_to_peer(const struct sic_config *config,
                           char *error, size_t error_length)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    char service[16];
    time_t deadline;
    int fd = -1;
    int lookup;

    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    (void)snprintf(service, sizeof(service), "%u", config->control_port);
    lookup = getaddrinfo(config->peer_address, service, &hints, &addresses);
    if (lookup != 0) {
        sic_set_error(error, error_length, "cannot resolve %s: %s",
                      config->peer_address, gai_strerror(lookup));
        return -1;
    }
    deadline = time(NULL) + (time_t)config->connect_timeout_seconds;
    do {
        for (address = addresses; address != NULL; address = address->ai_next) {
            fd = socket(address->ai_family, address->ai_socktype,
                        address->ai_protocol);
            if (fd < 0) {
                continue;
            }
            if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
                set_socket_timeouts(fd);
                freeaddrinfo(addresses);
                return fd;
            }
            (void)close(fd);
            fd = -1;
        }
        if (time(NULL) < deadline) {
            struct timespec pause = {1, 0};
            (void)nanosleep(&pause, NULL);
        }
    } while (time(NULL) < deadline);

    sic_set_error(error, error_length, "cannot connect to %s:%u: %s",
                  config->peer_address, config->control_port, strerror(errno));
    freeaddrinfo(addresses);
    return -1;
}

static int accept_peer(const struct sic_config *config,
                       char *error, size_t error_length)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    char service[16];
    int listener = -1;
    int connection = -1;
    int enabled = 1;
    int lookup;

    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    (void)snprintf(service, sizeof(service), "%u", config->control_port);
    lookup = getaddrinfo(config->listen_address[0] != '\0'
                             ? config->listen_address
                             : NULL,
                         service, &hints, &addresses);
    if (lookup != 0) {
        sic_set_error(error, error_length, "cannot resolve listen address: %s",
                      gai_strerror(lookup));
        return -1;
    }
    for (address = addresses; address != NULL; address = address->ai_next) {
        listener = socket(address->ai_family, address->ai_socktype,
                          address->ai_protocol);
        if (listener < 0) {
            continue;
        }
        (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                         &enabled, sizeof(enabled));
        if (bind(listener, address->ai_addr, address->ai_addrlen) == 0 &&
            listen(listener, 1) == 0) {
            break;
        }
        (void)close(listener);
        listener = -1;
    }
    freeaddrinfo(addresses);
    if (listener < 0) {
        sic_set_error(error, error_length, "cannot listen on %s:%u: %s",
                      config->listen_address, config->control_port,
                      strerror(errno));
        return -1;
    }
    connection = accept(listener, NULL, NULL);
    if (connection < 0) {
        sic_set_error(error, error_length, "cannot accept peer: %s",
                      strerror(errno));
    } else {
        set_socket_timeouts(connection);
    }
    (void)close(listener);
    return connection;
}

int sic_handshake_run(const struct sic_config *config,
                      struct sic_session *session,
                      char *error, size_t error_length)
{
    int fd;
    int result;

    if (config->role == SIC_ROLE_DEVICE1) {
        fd = connect_to_peer(config, error, error_length);
    } else {
        fd = accept_peer(config, error, error_length);
    }
    if (fd < 0) {
        return -1;
    }
    result = sic_handshake_over_fd(fd, config, session, error, error_length);
    (void)shutdown(fd, SHUT_RDWR);
    (void)close(fd);
    return result;
}
