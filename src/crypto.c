#include "sic/crypto.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

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

int sic_session_init(struct sic_session *session,
                     const uint8_t tx_key[SIC_AES_KEY_LEN],
                     const uint8_t rx_key[SIC_AES_KEY_LEN],
                     const uint8_t tx_prefix[SIC_NONCE_PREFIX_LEN],
                     const uint8_t rx_prefix[SIC_NONCE_PREFIX_LEN],
                     const uint8_t session_id[SIC_SESSION_ID_LEN],
                     uint32_t replay_window, uint32_t counter_lookahead,
                     char *error, size_t error_length)
{
    if (session == NULL || tx_key == NULL || rx_key == NULL ||
        tx_prefix == NULL || rx_prefix == NULL || session_id == NULL ||
        replay_window == 0U || counter_lookahead == 0U) {
        sic_set_error(error, error_length, "invalid session parameters");
        return -1;
    }

    (void)memset(session, 0, sizeof(*session));
    session->replay.seen = calloc(replay_window, sizeof(uint8_t));
    if (session->replay.seen == NULL) {
        sic_set_error(error, error_length,
                      "cannot allocate replay window (%u entries)",
                      replay_window);
        return -1;
    }

    (void)memcpy(session->tx_key, tx_key, SIC_AES_KEY_LEN);
    (void)memcpy(session->rx_key, rx_key, SIC_AES_KEY_LEN);
    (void)memcpy(session->tx_nonce_prefix, tx_prefix,
                 SIC_NONCE_PREFIX_LEN);
    (void)memcpy(session->rx_nonce_prefix, rx_prefix,
                 SIC_NONCE_PREFIX_LEN);
    (void)memcpy(session->session_id, session_id, SIC_SESSION_ID_LEN);
    atomic_init(&session->tx_counter, 0U);
    session->replay.size = replay_window;
    session->replay.lookahead = counter_lookahead;
    session->initialized = 1;
    return 0;
}

void sic_session_clear(struct sic_session *session)
{
    if (session == NULL) {
        return;
    }
    if (session->replay.seen != NULL) {
        sic_secure_zero(session->replay.seen, session->replay.size);
        free(session->replay.seen);
    }
    sic_secure_zero(session, sizeof(*session));
}

void sic_make_nonce(const uint8_t prefix[SIC_NONCE_PREFIX_LEN],
                    uint64_t counter,
                    uint8_t nonce[SIC_GCM_NONCE_LEN])
{
    size_t index;

    (void)memcpy(nonce, prefix, SIC_NONCE_PREFIX_LEN);
    for (index = 0U; index < 8U; ++index) {
        nonce[SIC_NONCE_PREFIX_LEN + index] =
            (uint8_t)(counter >> (56U - (unsigned int)(index * 8U)));
    }
}

int sic_aes_gcm_encrypt(const uint8_t key[SIC_AES_KEY_LEN],
                        const uint8_t nonce[SIC_GCM_NONCE_LEN],
                        const uint8_t *aad, size_t aad_length,
                        const uint8_t *plaintext, size_t plaintext_length,
                        uint8_t *ciphertext,
                        uint8_t tag[SIC_GCM_TAG_LEN],
                        char *error, size_t error_length)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *context = NULL;
    int output_length = 0;
    int final_length = 0;
    int result = -1;

    if (plaintext_length > (size_t)INT_MAX || aad_length > (size_t)INT_MAX) {
        sic_set_error(error, error_length, "AES-GCM input is too large");
        return -1;
    }

    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    context = EVP_CIPHER_CTX_new();
    if (cipher == NULL || context == NULL) {
        set_openssl_error(error, error_length, "AES-GCM initialization");
        goto cleanup;
    }
    if (EVP_EncryptInit_ex2(context, cipher, key, nonce, NULL) != 1) {
        set_openssl_error(error, error_length, "AES-GCM key setup");
        goto cleanup;
    }
    if (aad_length > 0U &&
        EVP_EncryptUpdate(context, NULL, &output_length, aad,
                          (int)aad_length) != 1) {
        set_openssl_error(error, error_length, "AES-GCM AAD processing");
        goto cleanup;
    }
    if (plaintext_length > 0U &&
        EVP_EncryptUpdate(context, ciphertext, &output_length, plaintext,
                          (int)plaintext_length) != 1) {
        set_openssl_error(error, error_length, "AES-GCM encryption");
        goto cleanup;
    }
    if (EVP_EncryptFinal_ex(context, ciphertext + output_length,
                            &final_length) != 1 ||
        (size_t)(output_length + final_length) != plaintext_length) {
        set_openssl_error(error, error_length, "AES-GCM finalization");
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                            (int)SIC_GCM_TAG_LEN, tag) != 1) {
        set_openssl_error(error, error_length, "AES-GCM tag extraction");
        goto cleanup;
    }
    result = 0;

cleanup:
    EVP_CIPHER_CTX_free(context);
    EVP_CIPHER_free(cipher);
    return result;
}

int sic_aes_gcm_decrypt(const uint8_t key[SIC_AES_KEY_LEN],
                        const uint8_t nonce[SIC_GCM_NONCE_LEN],
                        const uint8_t *aad, size_t aad_length,
                        const uint8_t *ciphertext, size_t ciphertext_length,
                        const uint8_t tag[SIC_GCM_TAG_LEN],
                        uint8_t *plaintext)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *context = NULL;
    int output_length = 0;
    int final_length = 0;
    int result = -1;

    if (ciphertext_length > (size_t)INT_MAX || aad_length > (size_t)INT_MAX) {
        return -1;
    }
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    context = EVP_CIPHER_CTX_new();
    if (cipher == NULL || context == NULL) {
        goto cleanup;
    }
    if (EVP_DecryptInit_ex2(context, cipher, key, nonce, NULL) != 1) {
        goto cleanup;
    }
    if (aad_length > 0U &&
        EVP_DecryptUpdate(context, NULL, &output_length, aad,
                          (int)aad_length) != 1) {
        goto cleanup;
    }
    if (ciphertext_length > 0U &&
        EVP_DecryptUpdate(context, plaintext, &output_length, ciphertext,
                          (int)ciphertext_length) != 1) {
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG,
                            (int)SIC_GCM_TAG_LEN, (void *)tag) != 1) {
        goto cleanup;
    }
    if (EVP_DecryptFinal_ex(context, plaintext + output_length,
                            &final_length) != 1) {
        goto cleanup;
    }
    if ((size_t)(output_length + final_length) != ciphertext_length) {
        goto cleanup;
    }
    result = 0;

cleanup:
    EVP_CIPHER_CTX_free(context);
    EVP_CIPHER_free(cipher);
    return result;
}

static int reserve_counter(atomic_uint_fast64_t *counter, uint64_t *value)
{
    uint_fast64_t current = atomic_load_explicit(counter, memory_order_relaxed);

    for (;;) {
        if (current >= UINT64_MAX) {
            return -1;
        }
        if (atomic_compare_exchange_weak_explicit(
                counter, &current, current + 1U,
                memory_order_relaxed, memory_order_relaxed)) {
            *value = (uint64_t)current;
            return 0;
        }
    }
}

int sic_session_encrypt(struct sic_session *session,
                        const uint8_t *aad, size_t aad_length,
                        const uint8_t *plaintext, size_t plaintext_length,
                        uint8_t *ciphertext,
                        uint8_t tag[SIC_GCM_TAG_LEN],
                        uint64_t *used_counter,
                        char *error, size_t error_length)
{
    uint64_t counter;
    uint8_t nonce[SIC_GCM_NONCE_LEN];
    int result;

    if (session == NULL || session->initialized == 0) {
        sic_set_error(error, error_length, "session is not initialized");
        return -1;
    }
    if (reserve_counter(&session->tx_counter, &counter) != 0) {
        sic_set_error(error, error_length,
                      "AES-GCM packet counter is exhausted; rekey required");
        return -1;
    }
    sic_make_nonce(session->tx_nonce_prefix, counter, nonce);
    result = sic_aes_gcm_encrypt(session->tx_key, nonce, aad, aad_length,
                                 plaintext, plaintext_length, ciphertext, tag,
                                 error, error_length);
    sic_secure_zero(nonce, sizeof(nonce));
    if (result == 0 && used_counter != NULL) {
        *used_counter = counter;
    }
    return result;
}

static int replay_seen(const struct sic_replay_window *window,
                       uint64_t counter)
{
    if (window->initialized == 0 || counter > window->highest) {
        return 0;
    }
    if (window->highest - counter >= window->size) {
        return 1;
    }
    return window->seen[counter % window->size] != 0U;
}

static int replay_mark(struct sic_replay_window *window, uint64_t counter)
{
    if (window->initialized == 0) {
        (void)memset(window->seen, 0, window->size);
        window->highest = counter;
        window->seen[counter % window->size] = 1U;
        window->initialized = 1;
        return 0;
    }

    if (counter > window->highest) {
        uint64_t delta = counter - window->highest;
        if (delta >= window->size) {
            (void)memset(window->seen, 0, window->size);
        } else {
            uint64_t value;
            for (value = window->highest + 1U;; ++value) {
                window->seen[value % window->size] = 0U;
                if (value == counter) {
                    break;
                }
            }
        }
        window->highest = counter;
    } else if (window->highest - counter >= window->size) {
        return -1;
    }

    if (window->seen[counter % window->size] != 0U) {
        return -1;
    }
    window->seen[counter % window->size] = 1U;
    return 0;
}

static int try_counter(struct sic_session *session, uint64_t counter,
                       const uint8_t *aad, size_t aad_length,
                       const uint8_t *ciphertext, size_t ciphertext_length,
                       const uint8_t tag[SIC_GCM_TAG_LEN], uint8_t *plaintext)
{
    uint8_t nonce[SIC_GCM_NONCE_LEN];
    int result;

    if (replay_seen(&session->replay, counter) != 0) {
        return -1;
    }
    sic_make_nonce(session->rx_nonce_prefix, counter, nonce);
    result = sic_aes_gcm_decrypt(session->rx_key, nonce, aad, aad_length,
                                 ciphertext, ciphertext_length, tag, plaintext);
    sic_secure_zero(nonce, sizeof(nonce));
    if (result == 0 && replay_mark(&session->replay, counter) == 0) {
        return 0;
    }
    return -1;
}

int sic_session_decrypt(struct sic_session *session,
                        const uint8_t *aad, size_t aad_length,
                        const uint8_t *ciphertext, size_t ciphertext_length,
                        const uint8_t tag[SIC_GCM_TAG_LEN],
                        uint8_t *plaintext, uint64_t *used_counter,
                        char *error, size_t error_length)
{
    uint64_t first;
    uint64_t candidate;
    uint64_t remaining;

    if (session == NULL || session->initialized == 0) {
        sic_set_error(error, error_length, "session is not initialized");
        return -1;
    }

    first = session->replay.initialized != 0
                ? session->replay.highest
                : 0U;
    remaining = session->replay.lookahead;
    if (session->replay.initialized == 0 || first != UINT64_MAX) {
        candidate = session->replay.initialized != 0 ? first + 1U : 0U;
    } else {
        candidate = 0U;
        remaining = 0U;
    }
    while (remaining > 0U) {
        if (try_counter(session, candidate, aad, aad_length, ciphertext,
                        ciphertext_length, tag, plaintext) == 0) {
            if (used_counter != NULL) {
                *used_counter = candidate;
            }
            return 0;
        }
        --remaining;
        if (candidate == UINT64_MAX) {
            break;
        }
        ++candidate;
    }

    if (session->replay.initialized != 0) {
        uint64_t distance;
        for (distance = 0U; distance < session->replay.size &&
                            distance <= session->replay.highest;
             ++distance) {
            candidate = session->replay.highest - distance;
            if (try_counter(session, candidate, aad, aad_length, ciphertext,
                            ciphertext_length, tag, plaintext) == 0) {
                if (used_counter != NULL) {
                    *used_counter = candidate;
                }
                return 0;
            }
        }
    }

    if (ciphertext_length > 0U) {
        sic_secure_zero(plaintext, ciphertext_length);
    }
    sic_set_error(error, error_length,
                  "authentication failed, packet replayed, or counter outside window");
    return -1;
}
