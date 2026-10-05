#include "cJSON.h"
#include "server.h"
#include <arpa/inet.h>
#include <bits/socket.h>
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

int pwmngr_connect(const char *server_ip, uint16_t port) {

    struct sockaddr_in server_addr;

    socklen_t server_addr_len = sizeof(server_addr);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    if (server_fd >= 0) {
        printf("Already connected!\n");
        return 0;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("Failed to create socket!\n");
        return 1;
    }

    if (connect(server_fd, (struct sockaddr *)&server_addr, server_addr_len) < 0) {
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
    // cJSON *info    = cJSON_GetObjectItem(root, "info");

    printf("smtp verification %s\n",
           cJSON_GetObjectItem(root, "smtp_enabled")->type == cJSON_True ? "enabled" : "disabled");

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
#define SALT_LEN crypto_pwhash_SALTBYTES

#define TOKEN_LEN 32

int remote_create_account(char *email, uint8_t *username_hash, uint8_t *password_hash, uint8_t *auth_pk, uint8_t *salt,
                          uint64_t auth_seed_id) {

    if (!email || !username_hash || !password_hash || !auth_pk || !salt || auth_seed_id < 2) {
        printf("Invalid arguments passed to remote_create_account!\n");
        return -1;
    }

    char *username_hash_b64 = b64_encode(username_hash, UNAME_HASH_LEN);
    if (!username_hash_b64) {
        printf("Failed to encode username_hash as base64 string!\n");
        return -2;
    }

    char *password_hash_b64 = b64_encode(password_hash, PASSWD_HASH_LEN);
    if (!password_hash_b64) {
        printf("Failed to encode password_hash as base64 string!\n");
        return -2;
    }

    char *auth_pk_b64 = b64_encode(auth_pk, AUTH_PK_LEN);
    if (!auth_pk_b64) {
        printf("Failed to encode auth_pk as base64 string!\n");
        return -2;
    }

    char *salt_b64 = b64_encode(salt, SALT_LEN);
    if (!salt_b64) {
        printf("Failed to encode salt as base64 string!\n");
        return -2;
    }

    char auth_seed_id_str[25];
    for (int i = 0; i / 2 < (int)sizeof(uint64_t); i += 2)
        snprintf(auth_seed_id_str + i, sizeof(auth_seed_id_str) - i, "%02x",
                 *(uint8_t *)(((uint8_t *)&auth_seed_id) + i));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "request", "CREATEACCOUNT");
    cJSON_AddStringToObject(root, "email", email);
    cJSON_AddStringToObject(root, "username_hash", username_hash_b64);
    cJSON_AddStringToObject(root, "password_hash", password_hash_b64);
    cJSON_AddStringToObject(root, "auth_pk", auth_pk_b64);
    cJSON_AddStringToObject(root, "auth_seed_id", auth_seed_id_str);
    cJSON_AddStringToObject(root, "salt", salt_b64);

    free(username_hash_b64);
    free(password_hash_b64);
    free(auth_pk_b64);
    free(salt_b64);

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

int remote_update_account(char *current_email, char *email, uint8_t *username_hash, uint8_t *password_hash,
                          uint8_t *auth_pk, uint8_t *salt, uint64_t auth_seed_id) {

    if (!current_email || !auth_pk || auth_seed_id < 2) {
        printf("Invalid arguments passed to remote_update_account!\n");
        return -1;
    }

    char *username_hash_b64 = b64_encode(username_hash, UNAME_HASH_LEN);
    if (username_hash && !username_hash_b64) {
        printf("Failed to encode username_hash as base64 string!\n");
        return -2;
    }

    char *password_hash_b64 = b64_encode(password_hash, PASSWD_HASH_LEN);
    if (password_hash && !password_hash_b64) {
        printf("Failed to encode password_hash as base64 string!\n");
        return -2;
    }

    char *auth_pk_b64 = b64_encode(auth_pk, AUTH_PK_LEN);
    if (!auth_pk_b64) {
        printf("Failed to encode auth_pk as base64 string!\n");
        return -2;
    }

    char *salt_b64 = b64_encode(salt, SALT_LEN);
    if (salt && !salt_b64) {
        printf("Failed to encode salt as base64 string!\n");
        return -2;
    }

    char auth_seed_id_str[25];
    for (int i = 0; i / 2 < (int)sizeof(uint64_t); i += 2)
        snprintf(auth_seed_id_str + i, sizeof(auth_seed_id_str) - i, "%02x",
                 *(uint8_t *)(((uint8_t *)&auth_seed_id) + i));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "request", "CREATEACCOUNT");
    cJSON_AddStringToObject(root, "email", current_email);
    if (email)
        cJSON_AddStringToObject(root, "new_email", email);
    if (username_hash_b64)
        cJSON_AddStringToObject(root, "new_username_hash", username_hash_b64);
    if (password_hash_b64)
        cJSON_AddStringToObject(root, "new_password_hash", password_hash_b64);
    cJSON_AddStringToObject(root, "new_auth_pk", auth_pk_b64);
    cJSON_AddStringToObject(root, "new_auth_seed_id", auth_seed_id_str);
    if (salt)
        cJSON_AddStringToObject(root, "new_salt", salt_b64);

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
        printf("Failed to send UPDATEACCOUNT request! (send_packet returned %d)\n", sent_len);
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

#define CREATEACC_RESEND 0
#define UPDATEACC_RESEND 1

int request_code_resend(char *email, int mode, char *old_email, char *token_b64) {
    if (!email) {
        printf("No email provided!\n");
        return -1;
    }

    if (mode && (!token_b64 || !old_email)) {
        printf("Missing token/old email!\n");
        return -1;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "request", !mode ? "CREATEACCOUNT" : "UPDATEACCOUNT");
    if (mode) {
        cJSON_AddStringToObject(root, "email", old_email);
        cJSON_AddStringToObject(root, "token", token_b64);
        cJSON_AddStringToObject(root, "new_email", email);
    } else
        cJSON_AddStringToObject(root, "email", email);
    cJSON_AddBoolToObject(root, "request_resend", cJSON_True);

    char    *request_j    = cJSON_PrintUnformatted(root);
    uint8_t *request_data = ec_malloc(strlen("REQUEST") + strlen(request_j) + 1);
    sprintf((char *)request_data, "REQUEST%s", request_j);
    char response[1024];
    int  sent_len = send_packet(request_data, strlen((char *)request_data), (uint8_t *)response, sizeof(response));
    free(request_data);
    if (sent_len <= 0) {
        printf("Failed to resend %s request! (send_packet returned %d)\n", !mode ? "CREATEACCOUNT" : "UPDATEACCOUNT",
               sent_len);
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

int finish_update_account(int verification_code, char *email, char *old_email, char *token_b64) {

    int req_len = strlen("DATA") + sizeof(uint32_t) + sizeof(uint16_t) * 2 + strlen(email) + strlen(old_email);

    int      token_len;
    uint8_t *token = b64_decode(token_b64, &token_len);
    if (!token || token_len != TOKEN_LEN) {
        if (token)
            free(token);
        printf("Invalid token!\n");
        return -1;
    }

    uint16_t email_len     = strlen(email);
    uint16_t old_email_len = strlen(old_email);

    uint8_t *request_data     = ec_malloc(req_len);
    int      written_data_len = 0;
    memcpy(request_data + written_data_len, "DATA", strlen("DATA"));
    written_data_len += strlen("DATA");
    memcpy(request_data + written_data_len, token, TOKEN_LEN);
    written_data_len += TOKEN_LEN;
    memcpy(request_data + written_data_len, (uint32_t *)&verification_code, sizeof(uint32_t));
    written_data_len += sizeof(uint32_t);
    memcpy(request_data + written_data_len, &email_len, sizeof(uint16_t));
    written_data_len += sizeof(uint16_t);
    memcpy(request_data + written_data_len, email, email_len);
    written_data_len += email_len;
    memcpy(request_data + written_data_len, &old_email_len, sizeof(uint16_t));
    written_data_len += sizeof(uint16_t);
    memcpy(request_data + written_data_len, old_email, old_email_len);
    written_data_len += old_email_len;

    if (req_len != written_data_len) {
        free(request_data);
        printf("Invalid data length! (bug)\n");
        return -2;
    }

    char response[1024];
    int  sent_len = send_packet(request_data, written_data_len, (uint8_t *)response, sizeof(response));
    free(request_data);

    if (sent_len <= 0) {
        printf("Failed to send verification code for CREATEACCOUNT request! (send_packet returned %d)\n", sent_len);
        return -3;
    }

    cJSON *response_root = cJSON_Parse(response);
    if (!response_root) {
        printf("Failed to parse server response!\n");
        return -4;
    }

    int code_check_res = check_response_code(response_root);
    cJSON_Delete(response_root);

    if (code_check_res < 0)
        return code_check_res - 4;

    return 0;
}

#define KEY_LEN crypto_secretbox_KEYBYTES
#define PK_LEN crypto_sign_PUBLICKEYBYTES
#define SK_LEN crypto_sign_SECRETKEYBYTES

#define CHALLENGE_LEN 32
#define SIGNATURE_LEN crypto_sign_BYTES

uint8_t *remote_auth(char *email, uint8_t *auth_sk) {

    if (!email || !strlen(email) || !auth_sk) {
        printf("Missing email/auth_pk\n");
        return NULL;
    }

    cJSON *auth_req_j = cJSON_CreateObject();
    cJSON_AddStringToObject(auth_req_j, "request", "AUTH");
    cJSON_AddStringToObject(auth_req_j, "email", email);

    char *auth_req_str = cJSON_PrintUnformatted(auth_req_j);
    cJSON_Delete(auth_req_j);

    char *auth_req_buf = ec_malloc(strlen("REQUEST") + strlen(auth_req_str));
    sprintf(auth_req_buf, "REQUEST%s", auth_req_str);
    free(auth_req_str);

    char auth_req_response[1024];
    int  sent_len = send_packet((uint8_t *)auth_req_buf, strlen(auth_req_buf), (uint8_t *)auth_req_response,
                                sizeof(auth_req_response));
    free(auth_req_buf);
    if (sent_len <= 0) {
        printf("Failed to send AUTH request! (send_packet returned %d)\n", sent_len);
        return NULL;
    }

    cJSON *auth_req_response_j = cJSON_Parse(auth_req_response);
    if (!auth_req_response_j) {
        printf("Failed to parse server response!\n");
        return NULL;
    }

    int code_check_res = check_response_code(auth_req_response_j);

    if (code_check_res != -3) { // DATA_WAIT
        cJSON_Delete(auth_req_response_j);
        printf("Unexpected response from server!\n");
        return NULL;
    }

    cJSON *challenge_obj = cJSON_GetObjectItem(auth_req_response_j, "challenge");
    char  *challenge_b64 = NULL;
    if (!challenge_obj || !cJSON_IsString(challenge_obj) ||
        !strlen((challenge_b64 = cJSON_GetStringValue(challenge_obj)))) {
        cJSON_Delete(auth_req_response_j);
        printf("Server response did not contain challenge!\n");
        return NULL;
    }

    int      challenge_len;
    uint8_t *challenge = b64_decode(challenge_b64, &challenge_len);
    cJSON_Delete(auth_req_response_j);
    if (!challenge || challenge_len != CHALLENGE_LEN) {
        if (challenge)
            free(challenge);
        printf("Failed to decode challenge!\n");
        return NULL;
    }

    uint8_t sig[SIGNATURE_LEN];
    crypto_sign_detached(sig, NULL, challenge, CHALLENGE_LEN, auth_sk);

    uint8_t *auth_fin_data = ec_malloc(strlen("DATA") + SIGNATURE_LEN + strlen(email));
    memcpy(auth_fin_data, "DATA", 4);
    memcpy(auth_fin_data + strlen("DATA"), sig, SIGNATURE_LEN);
    memcpy(auth_fin_data + 4 + SIGNATURE_LEN, email, strlen(email));

    char auth_fin_response[1024];
    int  fin_sent_len = send_packet(auth_fin_data, strlen("DATA") + SIGNATURE_LEN + strlen(email),
                                    (uint8_t *)auth_fin_response, sizeof(auth_fin_response));
    free(auth_fin_data);

    if (fin_sent_len <= 0) {
        printf("Failed to send challenge signature for AUTH request! (send_packet returned %d)\n", fin_sent_len);
        return NULL;
    }

    cJSON *auth_fin_response_j = cJSON_Parse(auth_fin_response);
    if (!auth_fin_response_j) {
        printf("Failed to parse server response!\n");
        return NULL;
    }

    int fin_code_check_res = check_response_code(auth_fin_response_j);

    if (fin_code_check_res < 0) {
        cJSON_Delete(auth_fin_response_j);
        return NULL;
    }

    cJSON *token_obj = cJSON_GetObjectItem(auth_fin_response_j, "token");
    if (!token_obj || !cJSON_IsString(token_obj)) {
        cJSON_Delete(auth_fin_response_j);
        printf("Server failed to return token!\n");
        return NULL;
    }

    int      token_len;
    uint8_t *token = b64_decode(cJSON_GetStringValue(token_obj), &token_len);
    if (!token || token_len != TOKEN_LEN) {
        if (token)
            free(token);
        printf("Server returned invalid token!\n");
        return NULL;
    }

    return token;
}

int remote_get_account_info(char *email, char **salt, uint64_t *auth_seed_id) {

    if (!email) {
        printf("Missing email!\n");
        return -1;
    }

    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "request", "GETACCOUNTINFO");
    cJSON_AddStringToObject(request, "email", email);

    char *request_j = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);

    uint8_t *request_buf = ec_malloc(strlen(request_j) + strlen("REQUEST") + 1);
    snprintf(request_buf, strlen(request_j) + strlen("REQUEST") + 1, "REQUEST%s", request_j);

    char response_buf[1024];
    int  sent_len =
        send_packet(request_buf, strlen(request_j) + strlen("REQUEST"), (uint8_t *)response_buf, sizeof(response_buf));

    free(request_buf);

    if (sent_len <= 0) {
        printf("Failed to send GETACCOUNTINFO request! (send_packet returned %d)\n", sent_len);
        return -2;
    }

    cJSON *response_root = cJSON_Parse(response_buf);
    if (!response_root) {
        printf("Failed to parse server response!\n");
        return -3;
    }

    char *auth_seed_id_str = NULL;
    char *salt_b64         = NULL;

    int code_check_res = check_response_code(response_root);
    if (!code_check_res) {
        cJSON *auth_seed_id_obj = cJSON_GetObjectItem(response_root, "auth_seed_id");
        cJSON *salt_obj         = cJSON_GetObjectItem(response_root, "salt");

        if (!auth_seed_id_obj || !salt_obj) {
            printf("Missing server response fields!\n");
            cJSON_Delete(response_root);
            return -4;
        }

        auth_seed_id_str = strdup(auth_seed_id_obj->valuestring);
        salt_b64         = strdup(salt_obj->valuestring);
    }
    cJSON_Delete(response_root);

    if (code_check_res < 0)
        return code_check_res - 5;

    uint8_t buf[8];
    for (int i = 0; i < 8; i++)
        sscanf(auth_seed_id_str + 2 * i, "%2hhx", &buf[i]);

    *auth_seed_id = ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48) | ((uint64_t)buf[2] << 40) |
                    ((uint64_t)buf[3] << 32) | ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16) |
                    ((uint64_t)buf[6] << 8) | ((uint64_t)buf[7]);
    free(auth_seed_id_str);

    int salt_len;
    *salt = b64_decode(salt_b64, &salt_len);
    free(salt_b64);

    if (!salt || salt_len != SALT_LEN) {
        if (*salt)
            free(*salt);
        printf("Invalid salt length!\n");
        return -5;
    }

    return 0;
}

int remote_import_account(char *email, char *token_b64) {
    return -1;
}

int remote_delete_account(char *email, char *token_b64) {
    return -1;
}

int remote_get_vault(char *email, char *token_b64, uint8_t **vault_buf) {
    return -1;
}

int remote_push_vault(char *email, char *token_b64, uint8_t *vault_buf) {
    return -1;
}

// Expects allocated buffers
int passwd_to_keys_with_salt(const char *password, uint8_t *salt, uint64_t auth_seed_id, uint8_t *vault_key,
                             uint8_t *auth_pk, uint8_t *auth_sk) {

    if (!password || !salt || !vault_key || !auth_pk || !auth_sk || auth_seed_id < 2)
        return -1;

    uint8_t mkey[crypto_kdf_KEYBYTES];

    if (crypto_pwhash(mkey, sizeof mkey, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT))
        return -2; // OOM

    uint8_t auth_seed[crypto_sign_SEEDBYTES];

    crypto_kdf_derive_from_key(vault_key, KEY_LEN, 1, "vault-key", mkey);
    crypto_kdf_derive_from_key(auth_seed, sizeof(auth_seed), auth_seed_id, "auth-seed", mkey);

    crypto_sign_seed_keypair(auth_pk, auth_sk, auth_seed);

    sodium_memzero(mkey, sizeof(mkey));
    sodium_memzero(auth_seed, sizeof(auth_seed));

    return 0;
}

int passwd_to_keys_new(const char *password, uint64_t *auth_seed_id, uint8_t *salt, uint8_t *vault_key,
                       uint8_t *auth_pk, uint8_t *auth_sk) {
    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(auth_seed_id, sizeof(uint64_t));
    if (*auth_seed_id < 2)
        *auth_seed_id += 2;
    return passwd_to_keys_with_salt(password, salt, *auth_seed_id, vault_key, auth_pk, auth_sk);
}

int main() {

    if (sodium_init() < 0)
        return -1;

    uint8_t *salt = b64_decode("Tb/HYKbbznQDv0FAfo+xSQ==", NULL);

    uint64_t auth_seed_id = 2;
    uint8_t  vault_key[KEY_LEN];
    uint8_t  auth_pk[PK_LEN];
    uint8_t  auth_sk[SK_LEN];
    passwd_to_keys_with_salt("test", salt, auth_seed_id, vault_key, auth_pk, auth_sk);

    if (pwmngr_connect("127.0.0.1", PORT)) {
        printf("Failed to connect to server!\n");
        return 1;
    }

    printf("Connection ok\n");

    // send requests
    uint8_t username_hash[UNAME_HASH_LEN];
    uint8_t password_hash[PASSWD_HASH_LEN];

    randombytes_buf(username_hash, sizeof(username_hash));
    randombytes_buf(password_hash, sizeof(password_hash));

    // if (remote_create_account("test@example.com", username_hash, password_hash, auth_pk, salt, auth_seed_id) == -5) {
    //     // server emailed verification code; get it from user and enter it here
    //     finish_create_account(292301, "test@example.com");
    // }

    uint8_t *token = remote_auth("test@example.com", auth_sk);
    if (!token) {
        printf("Failed to authenticate!\n");
        return 2;
    }
    printf("Got token %s\n", b64_encode(token, TOKEN_LEN));

    pwmngr_disconnect();

    SSL_CTX_free(ctx);
    ctx = NULL;
    return 0;
}
