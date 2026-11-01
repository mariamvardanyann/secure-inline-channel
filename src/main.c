#define _POSIX_C_SOURCE 200809L

#include "sic/config.h"
#include "sic/handshake.h"
#include "sic/nfqueue.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

static volatile sig_atomic_t stop_requested = 0;

static void signal_handler(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static void print_usage(const char *program)
{
    (void)fprintf(stderr,
                  "Usage: %s --config PATH\n"
                  "       %s --help\n",
                  program, program);
}

static void log_session_id(const struct sic_session *session)
{
    char text[SIC_SESSION_ID_LEN * 2U + 1U];
    size_t index;

    for (index = 0U; index < SIC_SESSION_ID_LEN; ++index) {
        (void)snprintf(text + index * 2U, 3U, "%02x",
                       session->session_id[index]);
    }
    text[sizeof(text) - 1U] = '\0';
    sic_log(SIC_LOG_INFO, "secure session established: id=%s", text);
}

int main(int argc, char **argv)
{
    struct sic_config config;
    struct sic_session session;
    struct sic_queue_stats encrypt_stats;
    struct sic_queue_stats decrypt_stats;
    struct sigaction action;
    char error[SIC_MAX_ERROR_LEN] = {0};
    const char *config_path = NULL;
    int index;
    int exit_code = 1;

    (void)memset(&config, 0, sizeof(config));
    (void)memset(&session, 0, sizeof(session));
    (void)memset(&encrypt_stats, 0, sizeof(encrypt_stats));
    (void)memset(&decrypt_stats, 0, sizeof(decrypt_stats));
    for (index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--config") == 0 && index + 1 < argc) {
            config_path = argv[++index];
        } else if (strcmp(argv[index], "--help") == 0 ||
                   strcmp(argv[index], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            print_usage(argv[0]);
            return 2;
        }
    }
    if (config_path == NULL) {
        print_usage(argv[0]);
        return 2;
    }
    if (sic_config_load(config_path, &config, error, sizeof(error)) != 0) {
        (void)fprintf(stderr, "configuration error: %s\n", error);
        goto cleanup;
    }
    sic_set_log_level(config.log_level);

    (void)memset(&action, 0, sizeof(action));
    action.sa_handler = signal_handler;
    (void)sigemptyset(&action.sa_mask);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGTERM, &action, NULL);

    sic_log(SIC_LOG_INFO, "starting as %s",
            config.role == SIC_ROLE_DEVICE1 ? "Device1" : "Device2");
    if (config.psk_length == 0U) {
        sic_log(SIC_LOG_WARN,
                "no PSK configured: DH is encrypted but not authenticated against MITM");
    }
    sic_log(SIC_LOG_INFO, "%s Diffie-Hellman control connection on port %u",
            config.role == SIC_ROLE_DEVICE1 ? "connecting for" : "waiting for",
            config.control_port);
    if (sic_handshake_run(&config, &session, error, sizeof(error)) != 0) {
        sic_log(SIC_LOG_ERROR, "secure handshake failed: %s", error);
        goto cleanup;
    }
    log_session_id(&session);

    if (sic_nfqueue_run(config.encrypt_queue, config.decrypt_queue,
                        &session, &stop_requested,
                        &encrypt_stats, &decrypt_stats,
                        error, sizeof(error)) != 0) {
        sic_log(SIC_LOG_ERROR, "packet loop failed: %s", error);
        goto cleanup;
    }
    exit_code = 0;

cleanup:
    if (session.initialized != 0) {
        sic_log(SIC_LOG_INFO,
                "encrypt stats: received=%llu modified=%llu passed=%llu dropped=%llu",
                (unsigned long long)encrypt_stats.received,
                (unsigned long long)encrypt_stats.modified,
                (unsigned long long)encrypt_stats.passed,
                (unsigned long long)encrypt_stats.dropped);
        sic_log(SIC_LOG_INFO,
                "decrypt stats: received=%llu modified=%llu passed=%llu dropped=%llu",
                (unsigned long long)decrypt_stats.received,
                (unsigned long long)decrypt_stats.modified,
                (unsigned long long)decrypt_stats.passed,
                (unsigned long long)decrypt_stats.dropped);
    }
    sic_session_clear(&session);
    sic_config_clear(&config);
    return exit_code;
}
