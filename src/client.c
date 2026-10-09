#include "cJSON.h"
#include "server.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MIN
#define MIN(a, b) (a < b ? a : b)
#endif

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

static uint8_t *sha_256_hash(uint8_t *data, size_t len) {
    uint8_t *hash_buf = ec_malloc(32);
    uint32_t out_len;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx)
        return NULL;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 || EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash_buf, &out_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);

    return hash_buf;
}

int check_response_code(cJSON *response) {
    cJSON *code = cJSON_GetObjectItem(response, "code");

    if (!code) {
        printf("Invalid response from server! (no response code)\n");
        return -1;
    }

    int val = cJSON_GetNumberValue(code);

    if (val != RESPONSE_OK) {
        printf("Server returned code '%d'\n", val);

        cJSON *err;
        if ((err = cJSON_GetObjectItem(response, "err")) && cJSON_IsString(err))
            printf("  %s\n", err->valuestring);
    }

    return val;
}

char *remote_get_server_info();

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
        server_fd = -1;
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

    char *server_version = remote_get_server_info();

    if (!server_version) {
        pwmngr_disconnect();
        return 6;
    }

    free(server_version);
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

#define HASH_LEN 32
#define UNAME_HASH_LEN 32
#define PASSWD_HASH_LEN 48
#define AUTH_PK_LEN 32
#define SALT_LEN crypto_pwhash_SALTBYTES

#define TOKEN_LEN 32

// returns server version string
char *remote_get_server_info() {
    char *get_info_req = "GETSERVERINFO";
    char  response_buf[1024];
    int   returned =
        send_packet((uint8_t *)get_info_req, strlen(get_info_req), (uint8_t *)response_buf, sizeof(response_buf));
    if (returned <= 0) {
        printf("send_packet failed!\n");
        return NULL;
    }

    cJSON *root = cJSON_Parse(response_buf);
    if (!root) {
        printf("Failed to parse server response!\n");
        return NULL;
    }

    cJSON *version = cJSON_GetObjectItem(root, "server_version");
    cJSON *info    = cJSON_GetObjectItem(root, "info");
    cJSON *smtp    = cJSON_GetObjectItem(root, "smtp_enabled");

    if (!version || !info || !smtp || !cJSON_IsString(version) || !cJSON_IsString(info) || !cJSON_IsBool(smtp)) {
        cJSON_Delete(root);
        printf("Invalid server response!\n");
        return NULL;
    }

    int code_check_res = check_response_code(root);

    if (code_check_res) {
        cJSON_Delete(root);
        return NULL;
    }

    if (strcmp(version->valuestring, SERVER_VERSION)) {
        printf("Server is running unsupported version!\n");
        cJSON_Delete(root);
        return NULL;
    }

    char *ret = strdup(info->valuestring);
    printf("smtp verification %s\n", smtp->type == cJSON_True ? "enabled" : "disabled");

    cJSON_Delete(root);

    return ret;
}

int remote_create_account(char *email, uint8_t *username_hash, uint8_t *password_hash, uint8_t *auth_pk, uint8_t *salt,
                          uint64_t auth_seed_id, char **token_out) {

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

    char auth_seed_id_str[17];
    u64_to_hex(auth_seed_id, auth_seed_id_str, sizeof(auth_seed_id_str));

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
    if (code_check_res < 0) {
        cJSON_Delete(response_root);
        return -3;
    }

    if (!code_check_res) {
        cJSON *token_obj = cJSON_GetObjectItem(response_root, "token");
        if (!token_obj || !cJSON_IsString(token_obj)) {
            printf("Missing/invalid field 'token' in server response!\n");
            cJSON_Delete(response_root);
            return -4;
        }
        *token_out = strdup(token_obj->valuestring);
    }

    cJSON_Delete(response_root);
    return code_check_res;
}

int remote_update_account(char *current_email, char *token_b64, char *email, uint8_t *username_hash,
                          uint8_t *password_hash, uint8_t *auth_pk, uint8_t *salt, uint64_t auth_seed_id) {

    if (!current_email || !token_b64 || !auth_pk || auth_seed_id < 2) {
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

    char auth_seed_id_str[17];
    u64_to_hex(auth_seed_id, auth_seed_id_str, sizeof(auth_seed_id_str));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "request", "UPDATEACCOUNT");
    cJSON_AddStringToObject(root, "email", current_email);
    cJSON_AddStringToObject(root, "token", token_b64);
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
        return -3;

    return code_check_res;
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

    if (code_check_res == DATA_WAIT)
        return 0;

    if (code_check_res)
        return -code_check_res - 4;

    return -2; // error because server didn't return DATA_WAIT
}

int finish_create_account(int verification_code, char *email, time_t *timestamp) {
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

    *timestamp = 0;

    int code_check_res = check_response_code(response_root);
    if (!code_check_res) {

        cJSON *timestamp_obj = cJSON_GetObjectItem(response_root, "last_modified");
        if (!timestamp_obj) {
            printf("Missing timestamp from server response!\n");
            cJSON_Delete(response_root);
            return -3;
        }

        *timestamp = hex_to_u64(timestamp_obj->valuestring);
    }
    cJSON_Delete(response_root);

    if (code_check_res < 0)
        return -4;

    return code_check_res;
}

int finish_update_account(int verification_code, char *email, char *old_email, char *token_b64, time_t *timestamp) {

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
    if (!code_check_res) {

        cJSON *timestamp_obj = cJSON_GetObjectItem(response_root, "last_modified");
        if (!timestamp_obj) {
            printf("Missing timestamp from server response!\n");
            cJSON_Delete(response_root);
            return -5;
        }

        *timestamp = hex_to_u64(timestamp_obj->valuestring);
    }
    cJSON_Delete(response_root);

    if (code_check_res < 0)
        return -6;

    return code_check_res;
}

#define KEY_LEN crypto_secretbox_KEYBYTES
#define PK_LEN crypto_sign_PUBLICKEYBYTES
#define SK_LEN crypto_sign_SECRETKEYBYTES

#define CHALLENGE_LEN 32
#define SIGNATURE_LEN crypto_sign_BYTES

int remote_auth(char *email, uint8_t *auth_sk, char **token_out) {

    if (!email || !strlen(email) || !auth_sk) {
        printf("Missing email/auth_pk\n");
        return -1;
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
        return -2;
    }

    cJSON *auth_req_response_j = cJSON_Parse(auth_req_response);
    if (!auth_req_response_j) {
        printf("Failed to parse server response!\n");
        return -3;
    }

    int code_check_res = check_response_code(auth_req_response_j);

    if (code_check_res != DATA_WAIT) { // DATA_WAIT
        cJSON_Delete(auth_req_response_j);
        printf("Unexpected response from server!\n");
        return -4;
    }

    cJSON *challenge_obj = cJSON_GetObjectItem(auth_req_response_j, "challenge");
    char  *challenge_b64 = NULL;
    if (!challenge_obj || !cJSON_IsString(challenge_obj) ||
        !strlen((challenge_b64 = cJSON_GetStringValue(challenge_obj)))) {
        cJSON_Delete(auth_req_response_j);
        printf("Server response did not contain challenge!\n");
        return -5;
    }

    int      challenge_len;
    uint8_t *challenge = b64_decode(challenge_b64, &challenge_len);
    cJSON_Delete(auth_req_response_j);
    if (!challenge || challenge_len != CHALLENGE_LEN) {
        if (challenge)
            free(challenge);
        printf("Failed to decode challenge!\n");
        return -6;
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
        return -7;
    }

    cJSON *auth_fin_response_j = cJSON_Parse(auth_fin_response);
    if (!auth_fin_response_j) {
        printf("Failed to parse server response!\n");
        return -8;
    }

    int fin_code_check_res = check_response_code(auth_fin_response_j);

    if (fin_code_check_res) {
        cJSON_Delete(auth_fin_response_j);
        return -9;
    }

    cJSON *token_obj = cJSON_GetObjectItem(auth_fin_response_j, "token");
    if (!token_obj || !cJSON_IsString(token_obj)) {
        cJSON_Delete(auth_fin_response_j);
        printf("Server failed to return token!\n");
        return -10;
    }

    int      token_len;
    uint8_t *token = b64_decode(cJSON_GetStringValue(token_obj), &token_len);
    if (token)
        free(token);
    if (!token || token_len != TOKEN_LEN) {
        cJSON_Delete(auth_fin_response_j);
        printf("Server returned invalid token!\n");
        return -11;
    }

    *token_out = strdup(token_obj->valuestring);
    cJSON_Delete(auth_fin_response_j);

    return 0;
}

int remote_invalidate_tokens(char *email, char *token_b64) {

    if (!email || !token_b64) {
        printf("Missing email/token!\n");
        return -1;
    }

    cJSON *req_j = cJSON_CreateObject();
    cJSON_AddStringToObject(req_j, "request", "INVALIDATETOKENS");
    cJSON_AddStringToObject(req_j, "email", email);
    cJSON_AddStringToObject(req_j, "token", token_b64);

    char *req_str = cJSON_PrintUnformatted(req_j);
    cJSON_Delete(req_j);

    char *req_buf = ec_malloc(strlen("REQUEST") + strlen(req_str));
    sprintf(req_buf, "REQUEST%s", req_str);
    free(req_str);

    char req_response[1024];
    int  sent_len = send_packet((uint8_t *)req_buf, strlen(req_buf), (uint8_t *)req_response, sizeof(req_response));
    free(req_buf);
    if (sent_len <= 0) {
        printf("Failed to send A request! (send_packet returned %d)\n", sent_len);
        return -2;
    }

    cJSON *req_response_j = cJSON_Parse(req_response);
    if (!req_response_j) {
        printf("Failed to parse server response!\n");
        return -3;
    }

    return check_response_code(req_response_j);
}

int remote_get_account_info(char *email, time_t *last_known_timestamp, uint8_t **salt, uint64_t *auth_seed_id) {

    if (!email) {
        printf("Missing email!\n");
        return -1;
    }

    char timestamp_str[17];
    u64_to_hex(*last_known_timestamp, timestamp_str, sizeof(timestamp_str));

    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "request", "GETACCOUNTINFO");
    cJSON_AddStringToObject(request, "email", email);
    cJSON_AddStringToObject(request, "last_known_timestamp", timestamp_str);

    char *request_j = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);

    uint8_t *request_buf = ec_malloc(strlen(request_j) + strlen("REQUEST") + 1);
    snprintf((char *)request_buf, strlen(request_j) + strlen("REQUEST") + 1, "REQUEST%s", request_j);

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

    char *auth_seed_id_str  = NULL;
    char *salt_b64          = NULL;
    char *last_modified_str = NULL;

    int code_check_res = check_response_code(response_root);
    if (!code_check_res) {
        cJSON *auth_seed_id_obj = cJSON_GetObjectItem(response_root, "auth_seed_id");
        cJSON *salt_obj         = cJSON_GetObjectItem(response_root, "salt");
        cJSON *timestamp_obj    = cJSON_GetObjectItem(response_root, "last_modified");

        if (!auth_seed_id_obj || !salt_obj || !timestamp_obj || !cJSON_IsString(auth_seed_id_obj) ||
            !cJSON_IsString(salt_obj) || !cJSON_IsString(timestamp_obj) ||
            strlen(auth_seed_id_obj->valuestring) != 16 || strlen(timestamp_obj->valuestring) != 16) {
            printf("Missing/invalid server response fields!\n");
            cJSON_Delete(response_root);
            return -4;
        }

        auth_seed_id_str  = strdup(auth_seed_id_obj->valuestring);
        salt_b64          = strdup(salt_obj->valuestring);
        last_modified_str = strdup(timestamp_obj->valuestring);
    } else if (code_check_res == E_CLIENTUPTODATE) {
        cJSON_Delete(response_root);
        return code_check_res;
    } else {
        cJSON_Delete(response_root);
        return -5;
    }

    *auth_seed_id = hex_to_u64(auth_seed_id_str);
    free(auth_seed_id_str);

    *(time_t *)last_known_timestamp = hex_to_u64(last_modified_str);
    free(last_modified_str);

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

int remote_import_account(char *email, char *token_b64, time_t *last_known_timestamp, uint8_t **uname_hash,
                          uint8_t **passwd_hash, uint8_t **salt, uint8_t **auth_pk, uint64_t *auth_seed_id) {
    if (!email || !token_b64 || !last_known_timestamp || !uname_hash || !passwd_hash || !salt || !auth_pk ||
        !auth_seed_id) {
        printf("Missing data inputs/outputs!\n");
        return -1;
    }

    char timestamp_str[17];
    u64_to_hex(*last_known_timestamp, timestamp_str, sizeof(timestamp_str));

    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "request", "IMPORTACCOUNT");
    cJSON_AddStringToObject(request, "email", email);
    cJSON_AddStringToObject(request, "token", token_b64);
    cJSON_AddStringToObject(request, "last_known_timestamp", timestamp_str);

    char *request_j = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);

    uint8_t *request_buf = ec_malloc(strlen(request_j) + strlen("REQUEST") + 1);
    snprintf((char *)request_buf, strlen(request_j) + strlen("REQUEST") + 1, "REQUEST%s", request_j);

    char response_buf[1024];
    int  sent_len =
        send_packet(request_buf, strlen(request_j) + strlen("REQUEST"), (uint8_t *)response_buf, sizeof(response_buf));

    free(request_buf);

    if (sent_len <= 0) {
        printf("Failed to send IMPORTACCOUNT request! (send_packet returned %d)\n", sent_len);
        return -2;
    }

    cJSON *response_root = cJSON_Parse(response_buf);
    if (!response_root) {
        printf("Failed to parse server response!\n");
        return -3;
    }

    char *uname_hash_b64    = NULL;
    char *passwd_hash_b64   = NULL;
    char *auth_pk_b64       = NULL;
    char *auth_seed_id_str  = NULL;
    char *salt_b64          = NULL;
    char *last_modified_str = NULL;

    int code_check_res = check_response_code(response_root);
    if (!code_check_res) {
        cJSON *uname_hash_obj   = cJSON_GetObjectItem(response_root, "uname_hash");
        cJSON *passwd_hash_obj  = cJSON_GetObjectItem(response_root, "passwd_hash");
        cJSON *auth_pk_obj      = cJSON_GetObjectItem(response_root, "auth_pk");
        cJSON *auth_seed_id_obj = cJSON_GetObjectItem(response_root, "auth_seed_id");
        cJSON *salt_obj         = cJSON_GetObjectItem(response_root, "salt");
        cJSON *timestamp_obj    = cJSON_GetObjectItem(response_root, "last_modified");

        if (!uname_hash_obj || !passwd_hash_obj || !auth_pk_obj || !auth_seed_id_obj || !salt_obj || !timestamp_obj ||
            !cJSON_IsString(uname_hash_obj) || !cJSON_IsString(passwd_hash_obj) || !cJSON_IsString(auth_pk_obj) ||
            !cJSON_IsString(auth_seed_id_obj) || !cJSON_IsString(salt_obj) || !cJSON_IsString(timestamp_obj) ||
            strlen(auth_seed_id_obj->valuestring) != 16 || strlen(timestamp_obj->valuestring) != 16) {
            printf("Missing/invalid server response fields!\n");
            cJSON_Delete(response_root);
            return -4;
        }

        uname_hash_b64    = strdup(uname_hash_obj->valuestring);
        passwd_hash_b64   = strdup(passwd_hash_obj->valuestring);
        auth_pk_b64       = strdup(auth_pk_obj->valuestring);
        auth_seed_id_str  = strdup(auth_seed_id_obj->valuestring);
        salt_b64          = strdup(salt_obj->valuestring);
        last_modified_str = strdup(timestamp_obj->valuestring);
        cJSON_Delete(response_root);
    } else if (code_check_res == E_CLIENTUPTODATE) {
        cJSON_Delete(response_root);
        return code_check_res;
    } else {
        cJSON_Delete(response_root);
        return -5;
    }

    *auth_seed_id = hex_to_u64(auth_seed_id_str);
    free(auth_seed_id_str);

    *(time_t *)last_known_timestamp = hex_to_u64(last_modified_str);
    free(last_modified_str);

    int uname_hash_len = 0;

    *uname_hash = b64_decode(uname_hash_b64, &uname_hash_len);
    free(uname_hash_b64);

    if (!*uname_hash || uname_hash_len != UNAME_HASH_LEN) {
        if (*uname_hash)
            free(*uname_hash);
        printf("Invalid uname_hash length!\n");
        return -5;
    }

    int passwd_hash_len = 0;

    *passwd_hash = b64_decode(passwd_hash_b64, &passwd_hash_len);
    free(passwd_hash_b64);

    if (!*passwd_hash || passwd_hash_len != PASSWD_HASH_LEN) {
        free(*uname_hash);
        if (*passwd_hash)
            free(*passwd_hash);
        printf("Invalid passwd_hash length!\n");
        return -5;
    }

    int auth_pk_len = 0;

    *auth_pk = b64_decode(auth_pk_b64, &auth_pk_len);
    free(auth_pk_b64);

    if (!*auth_pk || auth_pk_len != PK_LEN) {
        free(*uname_hash);
        free(*passwd_hash);
        if (*auth_pk)
            free(*auth_pk);
        printf("Invalid auth_pk length!\n");
        return -5;
    }

    int salt_len;
    *salt = b64_decode(salt_b64, &salt_len);
    free(salt_b64);

    if (!*salt || salt_len != SALT_LEN) {
        free(*uname_hash);
        free(*passwd_hash);
        free(*auth_pk);
        if (*salt)
            free(*salt);
        printf("Invalid salt length!\n");
        return -5;
    }

    return 0;
}

int remote_delete_account(char *email, char *token_b64) {
    if (!email || !token_b64) {
        printf("Missing email/token_b64!\n");
        return -1;
    }

    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "request", "DELETEACCOUNT");
    cJSON_AddStringToObject(request, "email", email);
    cJSON_AddStringToObject(request, "token", token_b64);

    char *request_j = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);

    uint8_t *request_buf = ec_malloc(strlen(request_j) + strlen("REQUEST") + 1);
    snprintf((char *)request_buf, strlen(request_j) + strlen("REQUEST") + 1, "REQUEST%s", request_j);

    char response_buf[1024];
    int  sent_len =
        send_packet(request_buf, strlen(request_j) + strlen("REQUEST"), (uint8_t *)response_buf, sizeof(response_buf));

    free(request_buf);

    if (sent_len <= 0) {
        printf("Failed to send DELETEACCOUNT request! (send_packet returned %d)\n", sent_len);
        return -2;
    }

    cJSON *response_root = cJSON_Parse(response_buf);
    if (!response_root) {
        printf("Failed to parse server response!\n");
        return -3;
    }

    int code_check_res = check_response_code(response_root);
    cJSON_Delete(response_root);
    return code_check_res;
}

cJSON *process_get_vault(char *request_j, uint8_t **out, int *out_len) {

    if (!ssl) {
        printf("TLS not initialized\n");
        return NULL;
    }

    int sent = SSL_write(ssl, request_j, strlen(request_j));
    if (sent <= 0) {
        int err = SSL_get_error(ssl, sent);
        printf("SSL_write failed: %d\n", err);
        return NULL;
    }
    if (sent != (int)strlen(request_j)) {
        printf("Partial TLS write: sent %d of %d bytes\n", sent, (int)strlen(request_j));
        return NULL;
    }

    // enough space for a 4096-byte transfer + metadata
#define MAX_VAULT_RESPONSE_LEN (VAULT_CHUNK_SIZE + 404)

    uint8_t *response_buf = ec_malloc(MAX_VAULT_RESPONSE_LEN);

    int received = SSL_read(ssl, response_buf, MAX_VAULT_RESPONSE_LEN - 1);
    if (received <= 0) {
        int err = SSL_get_error(ssl, received);
        printf("SSL_read failed: %d\n", err);
        return NULL;
    }
    response_buf[received] = 0; // NULL-terminate for cJSON

    cJSON *response = NULL;

    // zero the first 4 bytes so they can be checked for the server response
    // sodium_memzero(response_buf, 4);

    while (!((response = cJSON_Parse((char *)response_buf))) && !memcmp(response_buf, "DATA", 4)) {

        sodium_memzero(response_buf, 4);

        if (received < (int)(strlen("DATA") + sizeof(uint16_t))) {
            printf("Response length too short to contain header!\n");
            break;
        }

        uint16_t data_len = *(uint16_t *)(response_buf + strlen("DATA"));
        if (received != (int)(data_len + strlen("DATA") + sizeof(uint16_t))) {
            printf("Invalid data_len while reading vault from network!\n");
            break;
        }

        if (!*out)
            *out = ec_malloc(((*out_len = data_len)));
        else {
            uint8_t *new_ptr = ec_realloc(*out, ((*out_len += data_len)));
            if (!new_ptr) {
                free(*out);
                *out_len = 0;
                printf("Failed to reallocate vault output buffer!\n");
                break;
            }
            *out = new_ptr;
        }

        memcpy(*out + *out_len - data_len, response_buf + strlen("DATA") + sizeof(uint16_t), data_len);

        received = SSL_read(ssl, response_buf, MAX_VAULT_RESPONSE_LEN - 1);
        if (received <= 0) {
            int err = SSL_get_error(ssl, received);
            printf("SSL_read failed: %d\n", err);
            break;
        }
        response_buf[received] = 0; // NULL-terminate for cJSON
    }

    free(response_buf);
    return response;
}

int remote_get_vault(char *email, char *token_b64, time_t last_known_timestamp, int force, uint8_t **vault_buf,
                     int *vault_len) {

    if (!email || !token_b64) {
        printf("Missing email/token_b64!\n");
        return -1;
    }

    *vault_buf = NULL;
    *vault_len = 0;

    char timestamp_str[17];
    u64_to_hex(last_known_timestamp, timestamp_str, sizeof(timestamp_str));

    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "request", "GETVAULT");
    cJSON_AddStringToObject(request, "email", email);
    cJSON_AddStringToObject(request, "token", token_b64);
    // used only to help resolve sync conflicts (where server has client b's vault but client a has also
    // modified its vault, and thus can't get the vault from the server); also ignores hash verification
    cJSON_AddBoolToObject(request, "force", force);
    cJSON_AddStringToObject(request, "last_known_timestamp", timestamp_str);

    char *request_j = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);

    char *request_buf = ec_malloc(strlen(request_j) + strlen("REQUEST") + 1);
    snprintf(request_buf, strlen(request_j) + strlen("REQUEST") + 1, "REQUEST%s", request_j);
    free(request_j);

    // NULL on client/network error, set on server error/response
    cJSON *response = process_get_vault(request_buf, vault_buf, vault_len);
    free(request_buf);

    if (!response) {
        printf("Failed to receive server vault! (client/network error)\n");
        return -2;
    }

    int code_check = check_response_code(response);
    if (code_check) {
        cJSON_Delete(response);
        return code_check; // caller handles server-side error
    }

    cJSON *bytes_sent_obj = cJSON_GetObjectItem(response, "bytes_sent");
    if (!bytes_sent_obj || !cJSON_IsNumber(bytes_sent_obj)) {
        cJSON_Delete(response);
        printf("Missing/invalid response field 'bytes_sent'!\n");
        return -3;
    }

    if ((int)bytes_sent_obj->valuedouble != *vault_len) {
        cJSON_Delete(response);
        printf("Server report of bytes sent differs from actual bytes received!\n");
        return -3;
    }

    cJSON_Delete(response);

    VaultHeader *hdr = (VaultHeader *)*vault_buf;

    if (memcmp(hdr->magic, V_MAGIC, 6)) {
        printf("Invalid vault magic!\n");
        return -4;
    }

    if (hdr->version != V_VERSION) {
        printf("Invalid vault version!\n");
        return -4;
    }

    if (force) // server might return vault with invalid hash, don't bother checking
        return 0;

    uint8_t *hash = sha_256_hash((uint8_t *)hdr + 10 + HASH_LEN, *vault_len - 10 - HASH_LEN);
    if (!hash) {
        printf("Failed to hash vault data!\n");
        return -4;
    }

    if (memcmp(hash, hdr->hash, HASH_LEN)) {
        free(hash);
        printf("Verification failed for vault: invalid hash!\n");
        return -4;
    }

    free(hash);

    return 0; // request ok, vault stored in *vault_buf
}

int remote_push_vault(char *email, char *token_b64, uint8_t *vault_buf, int vault_len) {

    if (!email || !token_b64 || !vault_buf) {
        printf("Missing email/token_b64/vault_buf!\n");
        return -1;
    }

    if (vault_len <= (int)sizeof(VaultHeader)) {
        printf("Invalid vault length!\n");
        return -1;
    }

    VaultHeader *hdr = (VaultHeader *)vault_buf;

    if (memcmp(hdr->magic, V_MAGIC, 6)) {
        printf("Invalid vault magic!\n");
        return -1;
    }

    if (hdr->version != V_VERSION) {
        printf("Invalid vault version!\n");
        return -1;
    }

    uint8_t *hash = sha_256_hash((uint8_t *)hdr + 10 + HASH_LEN, vault_len - 10 - HASH_LEN);
    if (!hash) {
        printf("Failed to hash vault data!\n");
        return -1;
    }

    if (memcmp(hash, hdr->hash, HASH_LEN)) {
        free(hash);
        printf("Verification failed for vault: invalid hash!\n");
        return -1;
    }

    free(hash);

    time_t vault_timestamp = (time_t)hdr->timestamp;

    char timestamp_str[17];
    u64_to_hex(vault_timestamp, timestamp_str, sizeof(timestamp_str));

    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "request", "PUSHVAULT");
    cJSON_AddStringToObject(request, "email", email);
    cJSON_AddStringToObject(request, "token", token_b64);
    cJSON_AddStringToObject(request, "vault_timestamp", timestamp_str);

    char *request_j = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);

    uint8_t *request_buf = ec_malloc(strlen(request_j) + strlen("REQUEST") + 1);
    snprintf((char *)request_buf, strlen(request_j) + strlen("REQUEST") + 1, "REQUEST%s", request_j);

    char response_buf[1024];

    int req_sent_len =
        send_packet(request_buf, strlen((char *)request_buf), (uint8_t *)response_buf, sizeof(response_buf));

    free(request_buf);

    if (req_sent_len <= 0) {
        printf("Failed to send PUSHVAULT request! (send_packet returned %d)\n", req_sent_len);
        return -2;
    }

    cJSON *server_response = cJSON_Parse(response_buf);
    if (!server_response) {
        printf("Failed to parse initial server response!\n");
        return -3;
    }

    int server_response_code = check_response_code(server_response);
    if (server_response_code < 0)
        return -4;
    if (server_response_code != DATA_WAIT)
        return server_response_code;

    int bytes_sent = 0;
    int data_sent_len;

    int      token_len;
    uint8_t *raw_token = b64_decode(token_b64, &token_len);
    if (!raw_token || token_len != TOKEN_LEN) {
        if (raw_token)
            free(raw_token);
        printf("Failed to convert token to raw!\n");
        return -5;
    }

    uint8_t *packet =
        ec_malloc(strlen("DATA") + TOKEN_LEN + sizeof(uint16_t) + strlen(email) + sizeof(uint16_t) + VAULT_CHUNK_SIZE);

    int start_packet_bytes_written = 0;
    memcpy(packet, "DATA", 4);
    start_packet_bytes_written += 4;
    memcpy(packet + start_packet_bytes_written, raw_token, TOKEN_LEN);
    start_packet_bytes_written += TOKEN_LEN;
    uint16_t email_len = strlen(email);
    memcpy(packet + start_packet_bytes_written, (uint8_t *)&email_len, sizeof(uint16_t));
    start_packet_bytes_written += sizeof(uint16_t);
    memcpy(packet + start_packet_bytes_written, email, email_len);
    start_packet_bytes_written += email_len;

    while (server_response_code == DATA_WAIT) {

        // packet structure: \"DATA\" + token + (uint16_t)email_len + email + (uint16_t)data_len + partial vault

        uint16_t data_to_send_len = MIN(VAULT_CHUNK_SIZE, vault_len - bytes_sent);

        int packet_bytes_written = start_packet_bytes_written;
        memcpy(packet + packet_bytes_written, (uint8_t *)&data_to_send_len, sizeof(uint16_t));
        packet_bytes_written += sizeof(uint16_t);
        memcpy(packet + packet_bytes_written, vault_buf + bytes_sent, data_to_send_len);
        packet_bytes_written += data_to_send_len;

        data_sent_len = send_packet(packet, packet_bytes_written, (uint8_t *)response_buf, sizeof(response_buf));
        if (data_sent_len < 0) {
            free(raw_token);
            free(packet);
            printf("Failed to send data packet for vault transfer!\n");
            return -6;
        }
        bytes_sent += data_to_send_len;

        cJSON_Delete(server_response);
        server_response = cJSON_Parse(response_buf);
        if (!server_response) {
            free(raw_token);
            free(packet);
            printf("Failed to parse server response to data!\n");
            return -7;
        }

        server_response_code = check_response_code(server_response);
        if (server_response_code < 0) {
            free(raw_token);
            free(packet);
            printf("check_response_code returned < 0!\n");
            return -8;
        }
    }

    free(raw_token);
    free(packet);

    if (server_response_code) // caller must handle server-side error
        return server_response_code;

    cJSON *bytes_written_obj = cJSON_GetObjectItem(server_response, "bytes_written");
    if (!bytes_written_obj || !cJSON_IsNumber(bytes_written_obj)) {
        cJSON_Delete(server_response);
        printf("Missing/invalid bytes_written field in server response!\n");
        return -9;
    }

    if ((int)bytes_written_obj->valuedouble != vault_len) {
        cJSON_Delete(server_response);
        printf("Server received a different number of bytes than client sent!\n");
        return -10;
    }

    cJSON_Delete(server_response);

    return 0; // response ok, server successfully received and stored new vault
}

// Expects allocated buffers
int passwd_to_keys_with_salt(const char *password, uint8_t *salt, uint64_t auth_seed_id, uint8_t *vault_key,
                             uint8_t *auth_pk, uint8_t *auth_sk) {

    if (!password || !salt || !vault_key || !auth_pk || !auth_sk || auth_seed_id < 2)
        return -1;

    char *e_pass = ec_malloc(strlen(password) + 3 + 1);
    sprintf(e_pass, "%s-mk", password); // fixed salt so key != password hash

    uint8_t mkey[crypto_kdf_KEYBYTES];

    if (crypto_pwhash(mkey, sizeof mkey, e_pass, strlen(e_pass), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT)) {
        free(e_pass);
        return -2; // OOM
    }

    free(e_pass);

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

    char line_buf[1024];

    while (1) {
        printf("passwdmngr test client --> ");
        fgets(line_buf, sizeof(line_buf), stdin);
        line_buf[strlen(line_buf) - 1] = 0;
        if (!strcmp(line_buf, "exit"))
            break;
        if (!line_buf[0])
            continue;

        int   line_len = strlen(line_buf);
        char *raw_line = NULL;

        char **cmd_tokens     = ec_calloc(20, sizeof(char *)); // should be plenty
        int    num_cmd_tokens = 0;

        for (int i = 0; i < line_len; i++) {
            if ((i == 0 || line_buf[i] == line_buf[i + 1]) && line_buf[i] == ' ') {
                for (int j = i; j < line_len; j++)
                    line_buf[j] = line_buf[j + 1];

                line_len--;
                i--;
                continue;
            }

            if (line_buf[i] == ' ' || i == line_len - 1) { // ' ' as token deliminator
                if (num_cmd_tokens > 20) {
                    printf("Too many tokens!\n");
                    goto cont_loop;
                }
                if (line_buf[i] == ' ')
                    line_buf[i] = 0;
                if (!num_cmd_tokens) {
                    raw_line = strdup(line_buf + i + 1);

                    cmd_tokens[num_cmd_tokens] = line_buf;
                } else
                    cmd_tokens[num_cmd_tokens] =
                        cmd_tokens[num_cmd_tokens - 1] + strlen(cmd_tokens[num_cmd_tokens - 1]) + 1;
                num_cmd_tokens++;
            }
        }

        if (!cmd_tokens[0]) {
            printf("No request! (bug)\n");
            return 1;
        }

        if (!strcmp(cmd_tokens[0], "CONNECT")) {

            char     connect_ip[20] = "127.0.0.1";
            uint16_t port           = PORT;

            if (cmd_tokens[1]) { // use provided ip:port
                strncpy(connect_ip, cmd_tokens[1], sizeof(connect_ip) - 1);
                connect_ip[sizeof(connect_ip) - 1] = 0;

                char *colon = strchr(connect_ip, ':');
                if (colon) {
                    *colon = 0;
                    port   = (uint16_t)strtol(colon + 1, NULL, 10);
                    if (!port)
                        port = PORT;
                }
            }

            printf("Connecting to server...\n");
            if (pwmngr_connect(connect_ip, port))
                printf("Failed to connect to server!\n");
            else
                printf("Successfully connected to server\n");

        } else if (!strcmp(cmd_tokens[0], "DISCONNECT")) {

            printf("Disconnecting from server...\n");
            pwmngr_disconnect();
            printf("Disconnected\n");

        } else if (!strcmp(cmd_tokens[0], "GETSERVERINFO")) {

            printf("Getting server info...\n");
            char *info_str = remote_get_server_info();
            if (!info_str)
                printf("Failed to get server info!\n");
            else {
                printf("Server info:\n%s\n", info_str);
                free(info_str);
            }

        } else if (!strcmp(cmd_tokens[0], "CREATEACCOUNT")) { // <email> <test password>

            printf("Creating account...\n");

            if (!cmd_tokens[1] || !cmd_tokens[2]) {
                printf("Missing email/password!\n");
                goto cont_loop;
            }

            char *email        = cmd_tokens[1];
            char *new_password = cmd_tokens[2];

            uint8_t  salt[SALT_LEN];
            uint8_t  username_hash[UNAME_HASH_LEN];
            uint8_t  password_hash[PASSWD_HASH_LEN];
            uint8_t  vault_key[KEY_LEN];
            uint8_t  auth_pk[PK_LEN];
            uint8_t  auth_sk[SK_LEN];
            uint64_t auth_seed_id;

            char *token_b64 = NULL;

            randombytes_buf(username_hash, sizeof(username_hash));
            randombytes_buf(password_hash, sizeof(password_hash));

            passwd_to_keys_new(new_password, &auth_seed_id, salt, vault_key, auth_pk, auth_sk);

            int res =
                remote_create_account(email, username_hash, password_hash, auth_pk, salt, auth_seed_id, &token_b64);

            if (!res) {
                printf("Successfully created new account!\nToken: %s\n", token_b64);
                free(token_b64);
                goto cont_loop;
            }

            printf("Failed to create account! (%s error, code %d)\n", res < 0 ? "client" : "server", res);

        } else if (!strcmp(cmd_tokens[0], "UPDATEACCOUNT")) {
            // <current email> <current password> <base64 token> [new email] [FLAGS]{--uname | --passwd}

            printf("Updating account...\n");

            if (!cmd_tokens[1] || !cmd_tokens[2] || !cmd_tokens[3]) {
                printf("Missing current email/password/token!\n");
                goto cont_loop;
            }

            char    *new_email                          = NULL;
            uint8_t  new_password_hash[PASSWD_HASH_LEN] = {0};
            uint8_t  new_username_hash[UNAME_HASH_LEN]  = {0};
            uint8_t  salt[SALT_LEN];
            uint8_t  auth_sk[SK_LEN];
            uint8_t  vault_key[KEY_LEN];
            uint8_t  new_auth_pk[PK_LEN];
            uint64_t new_auth_seed_id;

            randombytes_buf(&new_auth_seed_id, sizeof(new_auth_seed_id));
            passwd_to_keys_new(cmd_tokens[2], &new_auth_seed_id, salt, vault_key, new_auth_pk, auth_sk);

            if (cmd_tokens[4] && cmd_tokens[4][0] != '-') {
                new_email = cmd_tokens[4];

                if (cmd_tokens[5]) {
                    if (!strcmp(cmd_tokens[5], "--uname"))
                        randombytes_buf(new_username_hash, sizeof(new_username_hash));
                    else if (!strcmp(cmd_tokens[5], "--passwd"))
                        randombytes_buf(new_password_hash, sizeof(new_password_hash));
                }

                if (cmd_tokens[6]) {
                    if (!strcmp(cmd_tokens[6], "--uname"))
                        randombytes_buf(new_username_hash, sizeof(new_username_hash));
                    else if (!strcmp(cmd_tokens[6], "--passwd"))
                        randombytes_buf(new_password_hash, sizeof(new_password_hash));
                }
            } else {
                if (cmd_tokens[4]) {
                    if (!strcmp(cmd_tokens[4], "--uname"))
                        randombytes_buf(new_username_hash, sizeof(new_username_hash));
                    else if (!strcmp(cmd_tokens[4], "--passwd"))
                        randombytes_buf(new_password_hash, sizeof(new_password_hash));
                }

                if (cmd_tokens[5]) {
                    if (!strcmp(cmd_tokens[5], "--uname"))
                        randombytes_buf(new_username_hash, sizeof(new_username_hash));
                    else if (!strcmp(cmd_tokens[5], "--passwd"))
                        randombytes_buf(new_password_hash, sizeof(new_password_hash));
                }
            }

            int res = remote_update_account(
                cmd_tokens[1], cmd_tokens[3], new_email, new_username_hash[0] ? new_username_hash : NULL,
                new_password_hash[0] ? new_password_hash : NULL, new_auth_pk, salt, new_auth_seed_id);

            if (!res) {
                printf("Successfully updated account!\n");
                goto cont_loop;
            }

            printf("Failed to update account! (%s error, code %d)\n", res < 0 ? "client" : "server", res);

        } else if (!strcmp(cmd_tokens[0], "GETACCOUNTINFO")) { // <email> [hex time_t timestamp]

            printf("Getting account info...\n");

            if (!cmd_tokens[1]) {
                printf("Missing email!\n");
                goto cont_loop;
            }

            time_t timestamp = 0;
            if (cmd_tokens[2])
                timestamp = strtol(cmd_tokens[2], NULL, 16);

            char    *salt_b64     = NULL;
            uint8_t *salt         = NULL;
            uint64_t auth_seed_id = 0;

            int res = remote_get_account_info(cmd_tokens[1], &timestamp, &salt, &auth_seed_id);

            char auth_seed_id_str[17];
            u64_to_hex(auth_seed_id, auth_seed_id_str, sizeof(auth_seed_id_str));

            if (!res) {
                salt_b64 = b64_encode(salt, SALT_LEN);
                printf("Got salt %s, auth_seed_id %s\n", salt_b64, auth_seed_id_str);
                free(salt);
                free(salt_b64);
                goto cont_loop;
            }

            printf("Failed to get account info! (%s error, code %d)\n", res < 0 ? "client" : "server", res);

        } else if (!strcmp(cmd_tokens[0], "IMPORTACCOUNT")) { // <email> <base64 token> [hex time_t timestamp]

            printf("Importing account...\n");

            if (!cmd_tokens[1] || !cmd_tokens[2]) {
                printf("Missing email/token!\n");
                goto cont_loop;
            }

            time_t timestamp = 0;
            if (cmd_tokens[3])
                timestamp = strtol(cmd_tokens[3], NULL, 16);

            uint8_t *uname_hash  = NULL;
            uint8_t *passwd_hash = NULL;
            uint8_t *salt        = NULL;
            uint8_t *auth_pk     = NULL;
            uint64_t auth_seed_id;

            int res = remote_import_account(cmd_tokens[1], cmd_tokens[2], &timestamp, &uname_hash, &passwd_hash, &salt,
                                            &auth_pk, &auth_seed_id);

            if (res) {
                printf("Failed to import account! (%s error, code %d)\n", res < 0 ? "client" : "server", res);
                goto cont_loop;
            }

            char *uname_hash_b64  = b64_encode(uname_hash, UNAME_HASH_LEN);
            char *passwd_hash_b64 = b64_encode(passwd_hash, PASSWD_HASH_LEN);
            char *salt_b64        = b64_encode(salt, SALT_LEN);
            char *auth_pk_b64     = b64_encode(auth_pk, PK_LEN);

            char auth_seed_id_str[17];
            char timestamp_str[17];
            u64_to_hex(auth_seed_id, auth_seed_id_str, sizeof(auth_seed_id_str));
            u64_to_hex(timestamp, timestamp_str, sizeof(timestamp_str));

            free(uname_hash);
            free(passwd_hash);
            free(salt);
            free(auth_pk);

            printf("Got account info:\nUsername hash: %s\nPassword hash: %s\nSalt: %s\nAuthentication public key: "
                   "%s\nAuthentication seed id: %s\nTimestamp: %s\n",
                   uname_hash_b64, passwd_hash_b64, salt_b64, auth_pk_b64, auth_seed_id_str, timestamp_str);

            if (uname_hash_b64)
                free(uname_hash_b64);
            if (passwd_hash_b64)
                free(passwd_hash_b64);
            if (salt_b64)
                free(salt_b64);
            if (auth_pk_b64)
                free(auth_pk_b64);

        } else if (!strcmp(cmd_tokens[0], "DELETEACCOUNT")) { // <email> <base64 token>

            printf("Deleting account...\n");

            if (!cmd_tokens[1] || !cmd_tokens[2]) {
                printf("Missing email/token!\n");
                goto cont_loop;
            }

            int res = remote_delete_account(cmd_tokens[1], cmd_tokens[2]);

            if (!res) {
                printf("Successfully deleted account\n");
                goto cont_loop;
            }

            printf("Failed to delete account! (%s error, code %d)\n", res < 0 ? "client" : "server", res);

        } else if (!strcmp(cmd_tokens[0], "AUTH")) { // <email> <password> <base64 salt> <hex uint64_t auth_seed_id>

            printf("Authenticating...\n");

            if (!cmd_tokens[1] || !cmd_tokens[2] || !cmd_tokens[3] || !cmd_tokens[4]) {
                printf("Missing email/password/salt/auth_seed_id!\n");
                goto cont_loop;
            }

            uint8_t *salt         = b64_decode(cmd_tokens[3], NULL);
            uint64_t auth_seed_id = strtoul(cmd_tokens[4], NULL, 16);

            uint8_t vault_key[KEY_LEN];
            uint8_t auth_pk[PK_LEN];
            uint8_t auth_sk[SK_LEN];

            passwd_to_keys_with_salt(cmd_tokens[2], salt, auth_seed_id, vault_key, auth_pk, auth_sk);
            free(salt);

            char *token_b64;
            int   res = remote_auth(cmd_tokens[1], auth_sk, &token_b64);

            if (!res) {
                printf("Token: %s\n", token_b64);
                free(token_b64);
                goto cont_loop;
            }

            printf("Authentication failed! (%s error, code %d)\n", res < 0 ? "client" : "server", res);

        } else if (!strcmp(cmd_tokens[0], "INVALIDATETOKENS")) {

            printf("Invalidating tokens...\n");

            if (!cmd_tokens[1] || !cmd_tokens[2]) {
                printf("Missing email/token!\n");
                goto cont_loop;
            }

            int res = remote_invalidate_tokens(cmd_tokens[1], cmd_tokens[2]);

            if (!res) {
                printf("Successfully invalidated all tokens for account!\n");
                goto cont_loop;
            }

            printf("Failed to invalidate tokens! (%s error, code %d)\n", res < 0 ? "client" : "server", res);

        } else if (!strcmp(cmd_tokens[0], "GETVAULT")) {

            printf("Getting vault...\n");

            if (!cmd_tokens[1] || !cmd_tokens[2] || !cmd_tokens[3]) {
                printf("Missing email/token/output path!\n");
                goto cont_loop;
            }

            time_t timestamp = 0;
            if (cmd_tokens[4])
                timestamp = strtol(cmd_tokens[4], NULL, 16);

            uint8_t *vault_buf;
            int      vault_len;

            int res = remote_get_vault(cmd_tokens[1], cmd_tokens[2], timestamp, 0, &vault_buf, &vault_len);

            if (!res) {

                printf("Got a %d byte vault from server! Writing to file...\n", vault_len);

                FILE *fp = fopen(cmd_tokens[3], "wb");
                if (!fp) {
                    printf("Failed to open vault file for writing!\n");
                    free(vault_buf);
                    goto cont_loop;
                }
                int written = 0;
                while (written < vault_len)
                    written += fwrite(vault_buf + written, 1, vault_len - written, fp);

                fclose(fp);
                free(vault_buf);

                printf("Done!\n");

                goto cont_loop;
            }

            printf("Failed to get vault from server! (%s error, code %d)\n", res < 0 ? "client" : "server", res);

        } else if (!strcmp(cmd_tokens[0], "PUSHVAULT")) {

            printf("Pushing vault...\n");

            if (!cmd_tokens[1] || !cmd_tokens[2] || !cmd_tokens[3]) {
                printf("Missing email/token/input path!\n");
                goto cont_loop;
            }

            FILE *fp = fopen(cmd_tokens[3], "rb");
            if (!fp) {
                printf("Failed to open vault file to send data!\n");
                goto cont_loop;
            }

            fseek(fp, 0, SEEK_END);
            long fsize = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            if (fsize < (long)sizeof(VaultHeader)) {
                fclose(fp);
                printf("Vault to small to contain header!\n");
                goto cont_loop;
            }

            uint8_t *vault_buf = ec_malloc(fsize);
            fread(vault_buf, 1, fsize, fp);

            fclose(fp);

            int res = remote_push_vault(cmd_tokens[1], cmd_tokens[2], vault_buf, fsize);
            free(vault_buf);

            if (!res) {
                printf("Successfully pushed vault to server!\n");
                goto cont_loop;
            }

            printf("Failed to push vault to server! (%s error, code %d)\n", res < 0 ? "client" : "server", res);

        } else if (!strcmp(cmd_tokens[0], "SENDRAW")) {

            if (!raw_line) {
                printf("Missing data to send!\n");
                goto cont_loop;
            }

            char response[1024];
            response[0] = 0;

            int received = send_packet((uint8_t *)raw_line, strlen(raw_line), (uint8_t *)response, sizeof(response));

            if (received > 0)
                response[received] = 0;

            printf("\nsend_packet returned %d\n\nServer response:\n%s\n", received, response);

        } else
            printf("Unknown request!\n");

    cont_loop:

        free(cmd_tokens);
        if (raw_line)
            free(raw_line);
    }

    return 0;
}
