#include "server.h"
#include "cJSON.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define SERVER_CRT "/etc/passwdmngrd/server.crt"
#define SERVER_KEY "/etc/passwdmngrd/server.key"
#define CA_CRT "/etc/passwdmngrd/ca.crt"

#define ACCOUNTS_FILE "/var/lib/passwdmngrd/accounts.bin"
#define VAULTS_DIR "/var/lib/passwdmngrd/vaults/"

#ifndef SERVER_INFO
#define SERVER_INFO "Password Manager Server - version 1.0"
#endif

enum LogLevel { PLOG_DEBUG, PLOG_INFO, PLOG_WARN, PLOG_ERROR, PLOG_FATAL };
typedef enum LogLevel LogLevel;

static void plog(LogLevel level, const char *fmt, ...);

void util_assert(int cond, char *fail_msg) {
    if (!cond) {
        plog(PLOG_FATAL, "Assertion failed: %s", fail_msg);
        exit(2);
    }
}

void wipe_mem(void *mem, size_t bytes) {
    memset(mem, 0, bytes);

#if defined(_MSC_VER)
    _ReadWriteBarrier();
#else
    __asm__ __volatile__("" : : "r"(mem) : "memory");
#endif
}

void *ec_malloc(size_t size) {
    void *ptr = malloc(size);
    util_assert(ptr != NULL, "malloc returned NULL pointer");
    return ptr;
}

void *ec_calloc(size_t nmeb, size_t size) {
    void *ptr = calloc(nmeb, size);
    util_assert(ptr != NULL, "calloc returned NULL pointer");
    return ptr;
}

void *ec_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    util_assert(new_ptr != NULL, "realloc returned NULL pointer");
    return new_ptr;
}

static char *vprintf_dup(const char *fmt, va_list args) {
    va_list args_copy;
    va_copy(args_copy, args);

    int req_size = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);

    if (req_size < 0) {
        return NULL;
    }

    char *buf = ec_malloc(req_size + 1);
    if (!buf)
        return NULL;

    vsnprintf(buf, req_size + 1, fmt, args);

    return buf;
}

static void plog(LogLevel level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    char *msg = vprintf_dup(fmt, args);

    int syslog_level;
    switch (level) {
    case PLOG_DEBUG:
        syslog_level = LOG_DEBUG;
        break;
    case PLOG_INFO:
        syslog_level = LOG_INFO;
        break;
    case PLOG_WARN:
        syslog_level = LOG_WARNING;
        break;
    case PLOG_ERROR:
        syslog_level = LOG_ERR;
        break;
    default:
        syslog_level = LOG_CRIT;
        break;
    }

    syslog(syslog_level, "%s", msg);

    va_end(args);
    free(msg);
}

#define L_DEBUG(msg) plog(PLOG_DEBUG, msg)
#define L_INFO(msg) plog(PLOG_INFO, msg)
#define L_WARN(msg) plog(PLOG_WARN, msg)
#define L_ERROR(msg) plog(PLOG_ERROR, msg)
#define L_FATAL(msg) plog(PLOG_FATAL, msg)

void openssl_log_errors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        const char *msg = ERR_error_string(err, NULL);
        plog(PLOG_ERROR, "OpenSSL error: %s", msg);
    }
}

int handle_request(char *request, char *response_buf, size_t response_buf_len) {

    if (!strcmp(request, "GETSERVERINFO")) {

        char server_info[768];

#ifdef NO_DETAILED_SERVER_INFO
        strncpy(server_info, SERVER_INFO, sizeof(server_info));
#else
        struct utsname info;
        uname(&info);

        char cpu_model[256] = {0};

        FILE *fp = fopen("/proc/cpuinfo", "r");

        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "model name", 10) == 0) {
                    char *colon = strchr(line, ':');
                    if (colon) {
                        strncpy(cpu_model, colon + 2, sizeof(cpu_model) - 1);
                        cpu_model[strcspn(cpu_model, "\n")] = 0;
                    }
                    break;
                }
            }
            fclose(fp);
        }

        snprintf(server_info, sizeof(server_info), "%s\n%s %s %s\n%s", SERVER_INFO, info.sysname, info.release,
                 info.machine, cpu_model);
#endif

        cJSON *root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "code", 0);
        cJSON_AddNumberToObject(root, "server_version", SERVER_VERSION);
        cJSON_AddStringToObject(root, "response", server_info);

        char *response = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);

        strncpy(response_buf, response, response_buf_len);
        response_buf[strlen(response)] = 0;
        free(response);
        return strlen(response_buf);
    }

    return 0;
}

void handle_client_tls(SSL *ssl) {
    char buf[4096];
    int  n;

    for (;;) {
        n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);

            if (err == SSL_ERROR_ZERO_RETURN) {
                plog(PLOG_INFO, "TLS connection closed cleanly");
            } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                continue;
            } else {
                openssl_log_errors();
                plog(PLOG_ERROR, "TLS read error");
            }

            break;
        }

        buf[n] = '\0';
        plog(PLOG_INFO, "Received request: %s", buf);

        char response[4096];
        int  rlen = handle_request(buf, response, sizeof(response));

        if (SSL_write(ssl, response, rlen) <= 0) {
            openssl_log_errors();
            plog(PLOG_ERROR, "TLS write error");
            break;
        }
    }
}

SSL_CTX *ctx = NULL;

#ifndef QUEUE_SIZE
#define QUEUE_SIZE 128
#endif
#ifndef NUM_THREADS
#define NUM_THREADS 4
#endif

int queue[QUEUE_SIZE];
int q_head = 0, q_tail = 0;

pthread_mutex_t q_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  q_cond  = PTHREAD_COND_INITIALIZER;

void *tls_consumer(void *arg) {
    (void)(arg);

    while (1) {
        pthread_mutex_lock(&q_mutex);

        while (q_head == q_tail) {
            pthread_cond_wait(&q_cond, &q_mutex);
        }

        int fd = queue[q_head];
        q_head = (q_head + 1) % QUEUE_SIZE;

        pthread_mutex_unlock(&q_mutex);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);

        if (SSL_accept(ssl) <= 0) {
            openssl_log_errors();
            SSL_free(ssl);
            close(fd);
            continue;
        }

        handle_client_tls(ssl);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }
}

int main() {

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        openssl_log_errors();
        return 1;
    }

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CRT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_load_verify_locations(ctx, CA_CRT, NULL) <= 0) {
        openssl_log_errors();
        return 1;
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_t tid;
        pthread_create(&tid, NULL, tls_consumer, NULL);
        pthread_detach(tid);
    }

    int                server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        L_FATAL("Failed to create socket\n");
        exit(1);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        L_FATAL("Failed to bind socket\n");
        exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        L_FATAL("Failed to prepare server_fd with listen\n");
        exit(1);
    }

    plog(PLOG_INFO, "Listening on port %d\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (client_fd < 0) {
            L_ERROR("Failed to accept connection");
            continue;
        }

        plog(PLOG_INFO, "Received connection from client '%s'", inet_ntoa(addr.sin_addr));

        pthread_mutex_lock(&q_mutex);

        int next_tail = (q_tail + 1) % QUEUE_SIZE;
        if (next_tail == q_head) {
            L_ERROR("Connection queue full, dropping client");
            pthread_mutex_unlock(&q_mutex);
            close(client_fd);
            continue;
        }

        queue[q_tail] = client_fd;
        q_tail        = next_tail;

        pthread_cond_signal(&q_cond);
        pthread_mutex_unlock(&q_mutex);
    }

    close(server_fd);
    return 0;
}