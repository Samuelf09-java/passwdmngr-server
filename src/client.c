#include "cJSON.h"
#include "server.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int server_fd = -1;

SSL_CTX *ctx = NULL;
SSL     *ssl = NULL;

void pwmngr_disconnect();
int  send_packet(uint8_t *data, int data_len, uint8_t *response_buf, int response_buf_size);

int pwmngr_connect(const struct sockaddr *server_addr, socklen_t server_addr_len) {

    if (server_fd >= 0) {
        printf("Already connected!\n");
        return 0;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("Failed to create socket!\n");
        return 1;
    }

    if (connect(server_fd, server_addr, server_addr_len) < 0) {
        printf("Failed to connect to server!\n");
        return 2;
    }

    if (!ctx) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL)) {
            printf("Failed to load CA file!\n");
            SSL_CTX_free(ctx);
            ctx = NULL;
            close(server_fd);
            server_fd = -1;
            return 3;
        }
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) <= 0) {
        printf("Failed to connect to server (handshake failed)!\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        ssl = NULL;
        close(server_fd);
        server_fd = -1;
        return 4;
    }

    X509 *cert   = SSL_get_peer_certificate(ssl);
    long  result = SSL_get_verify_result(ssl);

    if (result != X509_V_OK) {
        printf("Certificate verification failed: %ld\n", result);
        X509_free(cert);
        return 5;
    }
    X509_free(cert);

    char *get_info_req = "GETSERVERINFO";
    char *response_buf = malloc(1024);
    int   returned     = send_packet((uint8_t *)get_info_req, strlen(get_info_req), (uint8_t *)response_buf, 1024);
    if (returned <= 0) {
        printf("send_packet failed!\n");
        return 6;
    }

    cJSON *root    = cJSON_Parse(response_buf);
    cJSON *code    = cJSON_GetObjectItem(root, "code");
    cJSON *version = cJSON_GetObjectItem(root, "server_version");
    cJSON *info    = cJSON_GetObjectItem(root, "response");

    free(response_buf);

    if (!code) {
        printf("Invalid response from server! (no response code)\n");
        cJSON_Delete(root);
        pwmngr_disconnect();
        return 7;
    }

    if (cJSON_GetNumberValue(code) != 0) {
        printf("Server returned error: %d", (int)code->valuedouble);
        cJSON_Delete(root);
        pwmngr_disconnect();
        return 8;
    }

    if (cJSON_GetNumberValue(version) != SERVER_VERSION) {
        printf("Invalid response from server! (wrong version)\n");
        cJSON_Delete(root);
        pwmngr_disconnect();
        return 9;
    }

    if (info && cJSON_IsString(info)) // Debug print
        printf("Server info:\n%s\n", info->valuestring);

    cJSON_Delete(root);

    return 0;
}

void pwmngr_disconnect() {
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_fd);
    server_fd = -1;
    ssl       = NULL;
}

int send_packet(uint8_t *data, int data_len, uint8_t *response_buf, int response_buf_size) {
    if (!ssl) {
        printf("TLS not initialized\n");
        return -1;
    }

    int sent = SSL_write(ssl, data, data_len);
    if (sent <= 0) {
        int err = SSL_get_error(ssl, sent);
        printf("SSL_write failed: %d\n", err);
        return -2;
    }
    if (sent != data_len) {
        printf("Partial TLS write: sent %d of %d bytes\n", sent, data_len);
        return -3;
    }

    int received = SSL_read(ssl, response_buf, response_buf_size - 1);
    if (received <= 0) {
        int err = SSL_get_error(ssl, received);
        printf("SSL_read failed: %d\n", err);
        return -4;
    }

    return received;
}

int main() {

    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PORT);
    inet_pton(AF_INET, "10.0.0.161", &addr.sin_addr);

    if (pwmngr_connect((struct sockaddr *)&addr, addrlen)) {
        printf("Failed to connect to server!\n");
        return 1;
    }

    pwmngr_disconnect();

    SSL_CTX_free(ctx);
    ctx = NULL;
    return 0;
}