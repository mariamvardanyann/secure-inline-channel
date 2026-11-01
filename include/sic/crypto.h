#ifndef SIC_CRYPTO_H
#define SIC_CRYPTO_H

#include "sic/common.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

struct sic_replay_window {
    uint8_t *seen;
    uint32_t size;
    uint32_t lookahead;
    uint64_t highest;
    int initialized;
};

struct sic_session {
    uint8_t tx_key[SIC_AES_KEY_LEN];
    uint8_t rx_key[SIC_AES_KEY_LEN];
    uint8_t tx_nonce_prefix[SIC_NONCE_PREFIX_LEN];
    uint8_t rx_nonce_prefix[SIC_NONCE_PREFIX_LEN];
    uint8_t session_id[SIC_SESSION_ID_LEN];
    atomic_uint_fast64_t tx_counter;
    struct sic_replay_window replay;
    int initialized;
};

int sic_session_init(struct sic_session *session,
                     const uint8_t tx_key[SIC_AES_KEY_LEN],
                     const uint8_t rx_key[SIC_AES_KEY_LEN],
                     const uint8_t tx_prefix[SIC_NONCE_PREFIX_LEN],
                     const uint8_t rx_prefix[SIC_NONCE_PREFIX_LEN],
                     const uint8_t session_id[SIC_SESSION_ID_LEN],
                     uint32_t replay_window, uint32_t counter_lookahead,
                     char *error, size_t error_length);
void sic_session_clear(struct sic_session *session);

void sic_make_nonce(const uint8_t prefix[SIC_NONCE_PREFIX_LEN],
                    uint64_t counter,
                    uint8_t nonce[SIC_GCM_NONCE_LEN]);

int sic_aes_gcm_encrypt(const uint8_t key[SIC_AES_KEY_LEN],
                        const uint8_t nonce[SIC_GCM_NONCE_LEN],
                        const uint8_t *aad, size_t aad_length,
                        const uint8_t *plaintext, size_t plaintext_length,
                        uint8_t *ciphertext,
                        uint8_t tag[SIC_GCM_TAG_LEN],
                        char *error, size_t error_length);

int sic_aes_gcm_decrypt(const uint8_t key[SIC_AES_KEY_LEN],
                        const uint8_t nonce[SIC_GCM_NONCE_LEN],
                        const uint8_t *aad, size_t aad_length,
                        const uint8_t *ciphertext, size_t ciphertext_length,
                        const uint8_t tag[SIC_GCM_TAG_LEN],
                        uint8_t *plaintext);

int sic_session_encrypt(struct sic_session *session,
                        const uint8_t *aad, size_t aad_length,
                        const uint8_t *plaintext, size_t plaintext_length,
                        uint8_t *ciphertext,
                        uint8_t tag[SIC_GCM_TAG_LEN],
                        uint64_t *used_counter,
                        char *error, size_t error_length);

int sic_session_decrypt(struct sic_session *session,
                        const uint8_t *aad, size_t aad_length,
                        const uint8_t *ciphertext, size_t ciphertext_length,
                        const uint8_t tag[SIC_GCM_TAG_LEN],
                        uint8_t *plaintext, uint64_t *used_counter,
                        char *error, size_t error_length);

#endif
