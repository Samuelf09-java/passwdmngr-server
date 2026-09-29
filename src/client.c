#include "cJSON.h"
#include "server.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int server_fd = -1;

SSL_CTX *ctx = NULL;
SSL     *ssl = NULL;

void pwmngr_disconnect();
int  send_packet(uint8_t *data, int data_len, uint8_t *response_buf, int response_buf_size);

void util_assert(int cond, char *fail_msg) {
    if (!cond) {
        fprintf(stderr, "Assertion failed: %s", fail_msg);
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

char *b64_encode(const uint8_t *input, int input_len) {
    if (!input || input_len <= 0)
        return NULL;

    int   out_len = 4 * ((input_len + 2) / 3);
    char *out     = ec_malloc(out_len + 1);

    int written  = EVP_EncodeBlock((uint8_t *)out, input, input_len);
    out[written] = '\0';

    return out;
}

uint8_t *b64_decode(const char *input, int *out_len) {
    if (!input)
        return NULL;

    int input_len = strlen(input);

    int      max_len = (input_len * 3) / 4;
    uint8_t *out     = ec_malloc(max_len);

    int written = EVP_DecodeBlock(out, (const unsigned char *)input, input_len);

    while (input_len > 0 && input[input_len - 1] == '=') {
        written--;
        input_len--;
    }

    if (out_len)
        *out_len = written;

    return out;
}

int check_response_code(cJSON *response) {
    cJSON *code = cJSON_GetObjectItem(response, "code");

    if (!code) {
        printf("Invalid response from server! (no response code)\n");
        return -1;
    }

    int val = cJSON_GetNumberValue(code);

    if (val == DATA_WAIT) {
        return -3; // DATA_WAIT (waiting for more data, like a verification code or file)
    }

    if (val != RESPONSE_OK) {
        printf("Server returned code '%d'\n", val);

        cJSON *err;
        if ((err = cJSON_GetObjectItem(response, "err")) && cJSON_IsString(err))
            printf("  %s\n", err->valuestring);

        return -2;
    }

    return 0;
}

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
        if (!SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL)) { // TODO: use user-provided crt
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
    char *response_buf = ec_malloc(1024);
    int   returned     = send_packet((uint8_t *)get_info_req, strlen(get_info_req), (uint8_t *)response_buf, 1024);
    if (returned <= 0) {
        printf("send_packet failed!\n");
        return 6;
    }

    cJSON *root = cJSON_Parse(response_buf);
    if (!root) {
        printf("Failed to parse server response!\n");
        return 7;
    }

    cJSON *version = cJSON_GetObjectItem(root, "server_version");
    // cJSON *info    = cJSON_GetObjectItem(root, "response");

    free(response_buf);

    int code_check_res = check_response_code(root);

    if (code_check_res < 0) {
        cJSON_Delete(root);
        pwmngr_disconnect();
        return -code_check_res + 7;
    }

    if (cJSON_GetNumberValue(version) != SERVER_VERSION) {
        printf("Invalid response from server! (wrong version)\n");
        cJSON_Delete(root);
        pwmngr_disconnect();
        return 10;
    }

    // if (info && cJSON_IsString(info)) // Debug print
    //     printf("Server info:\n%s\n", info->valuestring);

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

#define UNAME_HASH_LEN 32
#define PASSWD_HASH_LEN 48
#define AUTH_PK_LEN 32

int remote_create_account(char *email, uint8_t *username_hash, uint8_t *password_hash, uint8_t *auth_pk) {

    if (!email || !username_hash || !password_hash || !auth_pk) {
        printf("Invalid arguments passed to remote_create_account!\n");
        return -1;
    }

    char *username_hash_b64 = b64_encode(username_hash, UNAME_HASH_LEN);
    if (!username_hash_b64) {
        printf("Failed to encode username_hash as base64 string!\n");
        return -2;
    }

    char *password_hash_b64 = b64_encode(password_hash, PASSWD_HASH_LEN);
    if (!username_hash_b64) {
        printf("Failed to encode password_hash as base64 string!\n");
        return -2;
    }

    char *auth_pk_b64 = b64_encode(auth_pk, AUTH_PK_LEN);
    if (!username_hash_b64) {
        printf("Failed to encode auth_pk as base64 string!\n");
        return -2;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "request", "CREATEACCOUNT");
    cJSON_AddStringToObject(root, "email", email);
    cJSON_AddStringToObject(root, "username_hash", username_hash_b64);
    cJSON_AddStringToObject(root, "password_hash", password_hash_b64);
    cJSON_AddStringToObject(root, "auth_pk", auth_pk_b64);

    free(username_hash_b64);
    free(password_hash_b64);
    free(auth_pk_b64);

    char    *request_j    = cJSON_PrintUnformatted(root);
    uint8_t *request_data = ec_malloc(strlen("REQUEST") + strlen(request_j) + 1);
    sprintf((char *)request_data, "REQUEST%s", request_j);
    char response[1024];
    int  sent_len = send_packet(request_data, strlen((char *)request_data), (uint8_t *)response, sizeof(response));
    free(request_data);
    if (sent_len <= 0) {
        printf("Failed to send CREATEACCOUNT request! (send_packet returned %d)\n", sent_len);
        return -1;
    }

    cJSON *response_root = cJSON_Parse(response);
    if (!response_root) {
        printf("Failed to parse server response!\n");
        return -2;
    }

    int code_check_res = check_response_code(response_root);
    cJSON_Delete(response_root);

    if (code_check_res < 0)
        return code_check_res - 2; // -5 = verification needed, caller should handle

    return 0;
}

int request_code_resend(char *email) {
    if (!email) {
        printf("No email provided!\n");
        return -1;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "request", "CREATEACCOUNT");
    cJSON_AddStringToObject(root, "email", email);
    cJSON_AddBoolToObject(root, "request_resend", cJSON_True);

    char    *request_j    = cJSON_PrintUnformatted(root);
    uint8_t *request_data = ec_malloc(strlen("REQUEST") + strlen(request_j) + 1);
    sprintf((char *)request_data, "REQUEST%s", request_j);
    char response[1024];
    int  sent_len = send_packet(request_data, strlen((char *)request_data), (uint8_t *)response, sizeof(response));
    free(request_data);
    if (sent_len <= 0) {
        printf("Failed to send CREATEACCOUNT request! (send_packet returned %d)\n", sent_len);
        return -1;
    }

    cJSON *response_root = cJSON_Parse(response);
    if (!response_root) {
        printf("Failed to parse server response!\n");
        return -2;
    }

    int code_check_res = check_response_code(response_root);
    cJSON_Delete(response_root);

    if (code_check_res == -3) // DATA_WAIT
        return 0;

    if (code_check_res < 0)
        return code_check_res - 2; // -5 = verification needed, caller should handle

    return -2; // error because server didn't return DATA_WAIT
}

int finish_create_account(int verification_code, char *email) {
    uint8_t *request_data = ec_malloc(strlen("DATA") + sizeof(uint32_t) + strlen(email));
    memcpy(request_data, "DATA", 4);
    memcpy(request_data + strlen("DATA"), (uint32_t *)&verification_code, sizeof(uint32_t));
    memcpy(request_data + 8, email, strlen(email));
    char response[1024];
    int  sent_len = send_packet(request_data, strlen("DATA") + sizeof(uint32_t) + strlen(email), (uint8_t *)response,
                                sizeof(response));
    free(request_data);

    if (sent_len <= 0) {
        printf("Failed to send verification code for CREATEACCOUNT request! (send_packet returned %d)\n", sent_len);
        return -1;
    }

    cJSON *response_root = cJSON_Parse(response);
    if (!response_root) {
        printf("Failed to parse server response!\n");
        return -2;
    }

    int code_check_res = check_response_code(response_root);
    cJSON_Delete(response_root);

    if (code_check_res < 0)
        return code_check_res - 2;

    return 0;
}

int main() {

    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    // inet_pton(AF_INET, server_ip, &addr.sin_addr);

    if (pwmngr_connect((struct sockaddr *)&addr, addrlen)) {
        printf("Failed to connect to server!\n");
        return 1;
    }

    printf("Connection ok\n");

    // send requests
    uint8_t username_hash[UNAME_HASH_LEN];
    uint8_t password_hash[PASSWD_HASH_LEN];
    uint8_t auth_pk[AUTH_PK_LEN];

    randombytes_buf(username_hash, sizeof(username_hash));
    randombytes_buf(password_hash, sizeof(password_hash));
    randombytes_buf(auth_pk, sizeof(auth_pk));

    if (remote_create_account("test@example.com", username_hash, password_hash, auth_pk) == -5) {
        request_code_resend("test@example.com");
        // server emailed verification code; get it from user and enter it here
        finish_create_account(725698, "test@example.com");
    }

    pwmngr_disconnect();

    SSL_CTX_free(ctx);
    ctx = NULL;
    return 0;
}
