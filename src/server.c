// suppress ide warnings about sigaction
#define _POSIX_C_SOURCE 200809L

#include "server.h"
#include "cJSON.h"
#include "vldmail.h"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <sodium.h>
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

#define SMTP_CONF_FILE "/var/lib/passwdmngrd/smtp.conf"
#define ACCOUNTS_FILE "/var/lib/passwdmngrd/accounts.bin"
#define TOKENS_FILE "/var/lib/passwdmngrd/tokens.bin"
#define VAULTS_DIR "/var/lib/passwdmngrd/vaults/"

#ifndef SERVER_INFO
#define SERVER_INFO "Password Manager Server - version 1.0"
#endif

#ifndef MAX
#define MAX(a, b) (a > b ? a : b)
#endif

#ifndef MIN
#define MIN(a, b) (a < b ? a : b)
#endif

enum LogLevel { PLOG_DEBUG, PLOG_INFO, PLOG_WARN, PLOG_ERROR, PLOG_FATAL };
typedef enum LogLevel LogLevel;

static void plog(LogLevel level, const char *fmt, ...);

static void util_assert(int cond, char *fail_msg) {
    if (!cond) {
        plog(PLOG_FATAL, "Assertion failed: %s", fail_msg);
        exit(2);
    }
}

static void *ec_malloc(size_t size) {
    void *ptr = malloc(size);
    util_assert(ptr != NULL, "malloc returned NULL pointer");
    return ptr;
}

static void *ec_calloc(size_t nmeb, size_t size) {
    void *ptr = calloc(nmeb, size);
    util_assert(ptr != NULL, "calloc returned NULL pointer");
    return ptr;
}

static void *ec_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    util_assert(new_ptr != NULL, "realloc returned NULL pointer");
    return new_ptr;
}

static char *b64_encode(const uint8_t *input, int input_len) {
    if (!input || input_len <= 0)
        return NULL;

    int   out_len = 4 * ((input_len + 2) / 3);
    char *out     = ec_malloc(out_len + 1);

    int written  = EVP_EncodeBlock((uint8_t *)out, input, input_len);
    out[written] = '\0';

    return out;
}

static uint8_t *b64_decode(const char *input, int *out_len) {
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

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t')
        s++;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\n')) {
        *end-- = '\0';
    }
    return s;
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

static void openssl_log_errors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        const char *msg = ERR_error_string(err, NULL);
        plog(PLOG_ERROR, "OpenSSL error: %s", msg);
    }
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

static char *hash_email(const char *email) {
    uint8_t *hash_bin = sha_256_hash((uint8_t *)email, strlen(email));

    char *email_hash = ec_malloc(65);
    if (!email_hash)
        return NULL;
    for (int i = 0; i < 32; i++)
        sprintf(&email_hash[i * 2], "%02x", hash_bin[i]);

    email_hash[64] = '\0';
    return email_hash;
}

static cJSON *server_error(int code, char *message) {
    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", code);
    if (message)
        cJSON_AddStringToObject(response, "err", message);
    return response;
}

#define SERVER_ACCOUNT_FILE_MAGIC "PMSACC"
#define SERVER_ACCOUNT_FILE_VERSION 1

#define TOKEN_FILE_MAGIC "PWMTOK"
#define TOKEN_FILE_VERSION 1

#define HASH_LEN 32
#define SALT_LEN crypto_pwhash_SALTBYTES
#define UNAME_HASH_LEN HASH_LEN
#define PASSWD_HASH_LEN HASH_LEN + SALT_LEN
#define AUTH_PK_LEN crypto_sign_PUBLICKEYBYTES
#define TOKEN_LEN HASH_LEN
#define CHALLENGE_LEN HASH_LEN
#define SIGNATURE_LEN crypto_sign_BYTES

typedef enum ExpectedData {
    D_NONE,
    D_CA_EMAIL_VERIFICATION_CODE,
    D_UA_EMAIL_VERIFICATION_CODE,
    D_CHALLENGE_RESPONSE,
    D_PWMNGR_FILE_TRANSFER,
} ExpectedData;

typedef struct __attribute__((packed)) ServerAccountHeader {
    char     magic[6];
    uint32_t version;
    uint8_t  hash[HASH_LEN];
    uint32_t num_accounts;
} ServerAccountHeader;

typedef struct __attribute__((packed)) ServerAccount {
    uint32_t user_id;
    uint8_t  uname_hash[UNAME_HASH_LEN];
    uint8_t  passwd_hash[PASSWD_HASH_LEN];
    uint8_t  auth_pk[AUTH_PK_LEN];
    uint8_t  salt[SALT_LEN];
    uint64_t auth_seed_id;
    int64_t  last_modified;
    uint16_t email_len;
    char    *email;
} ServerAccount;

typedef struct __attribute__((packed)) TokenFileHeader {
    char     magic[6];
    uint32_t version;
    uint8_t  hash[HASH_LEN];
    uint32_t num_tokens;
} TokenFileHeader;

typedef struct __attribute__((packed)) AuthToken {
    uint8_t  token[TOKEN_LEN];
    uint64_t expire_time;
    uint32_t user_id;
} AuthToken;

typedef struct SmtpConfig {
    int   use_smtp_verification;
    char *smtp_host;
    int   smtp_port;
    char *smtp_user;
    char *smtp_pass;
    char *smtp_tls;
    char *smtp_from;
} SmtpConfig;

typedef struct EmailVerificationCode {
    int            code;
    time_t         expire_time;
    ServerAccount *new_acc;
    char          *request_ip_src;
    ExpectedData   type;

} EmailVerificationCode;

SmtpConfig *smtp_config = NULL;

EmailVerificationCode *verification_codes      = NULL;
int                    num_outstanding_codes   = 0;
pthread_mutex_t        verification_codes_lock = PTHREAD_MUTEX_INITIALIZER;

ServerAccount *accounts          = NULL;
int            num_accounts      = 0;
int            accounts_modified = 0;

AuthToken *tokens          = NULL;
int        num_tokens      = 0;
int        tokens_modified = 0;

pthread_mutex_t accounts_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t tokens_lock   = PTHREAD_MUTEX_INITIALIZER;

typedef struct FileLockEntry {
    char                 *key;
    pthread_mutex_t       lock;
    struct FileLockEntry *next;
} FileLockEntry;

#define NUM_BUCKETS 256
static FileLockEntry  *file_lock_table[NUM_BUCKETS];
static pthread_mutex_t file_lock_table_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t djb2_hash(const char *file_key) {
    uint64_t h = 5381;
    int      c;
    while ((c = *file_key++))
        h = ((h << 5) + h) + c;
    return h % NUM_BUCKETS;
}

static pthread_mutex_t *get_file_lock(const char *file_key) {
    unsigned long h = djb2_hash(file_key);

    pthread_mutex_lock(&file_lock_table_lock);

    FileLockEntry *e = file_lock_table[h];
    while (e) {
        if (strcmp(e->key, file_key) == 0) {
            pthread_mutex_unlock(&file_lock_table_lock);
            return &e->lock;
        }
        e = e->next;
    }

    e      = ec_malloc(sizeof(FileLockEntry));
    e->key = strdup(file_key);
    pthread_mutex_init(&e->lock, NULL);
    e->next            = file_lock_table[h];
    file_lock_table[h] = e;

    pthread_mutex_unlock(&file_lock_table_lock);

    return &e->lock;
}

static void lock_file(const char *path) {
    pthread_mutex_t *lock = get_file_lock(path);
    pthread_mutex_lock(lock);
}

static void unlock_file(const char *path) {
    pthread_mutex_t *lock = get_file_lock(path);
    pthread_mutex_unlock(lock);
}

static inline int smtp_enabled() {
    return smtp_config && smtp_config->use_smtp_verification && smtp_config->smtp_host &&
           smtp_config->smtp_from; // && smtp_config->smtp_user && smtp_config->smtp_pass
}

static inline int gen_verification_code() {
    return randombytes_uniform(1000000);
}

static int load_smtp_config() {
    if (smtp_config) {
        L_ERROR("smtp config already loaded!");
        return -1;
    }

    lock_file(SMTP_CONF_FILE);
    FILE *fp = fopen(SMTP_CONF_FILE, "r");
    if (!fp) {
        unlock_file(SMTP_CONF_FILE);
        return -2;
    }

    smtp_config = ec_calloc(1, sizeof(SmtpConfig));

    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        if (!eq)
            continue;

        *eq       = '\0';
        char *key = trim(line);
        char *val = trim(eq + 1);

        if (!strcmp(key, "use_smtp_verification"))
            smtp_config->use_smtp_verification = (!strcmp(val, "true"));

        else if (!strcmp(key, "smtp_host"))
            smtp_config->smtp_host = strdup(val);

        else if (!strcmp(key, "smtp_port"))
            smtp_config->smtp_port = atoi(val);

        else if (!strcmp(key, "smtp_user"))
            smtp_config->smtp_user = strdup(val);

        else if (!strcmp(key, "smtp_pass"))
            smtp_config->smtp_pass = strdup(val);

        else if (!strcmp(key, "smtp_tls"))
            smtp_config->smtp_tls = strdup(val);

        else if (!strcmp(key, "smtp_from"))
            smtp_config->smtp_from = strdup(val);
    }

    fclose(fp);
    unlock_file(SMTP_CONF_FILE);
    return 0;
}

static void free_accounts() {
    pthread_mutex_lock(&accounts_lock);
    if (!accounts)
        return;
    for (int i = 0; i < num_accounts; i++)
        if (accounts[i].email)
            free(accounts[i].email);
    free(accounts);
    pthread_mutex_unlock(&accounts_lock);
}

static int save_accounts() {

    if (!accounts_modified)
        return 0; // nothing to do

    ServerAccountHeader *hdr = ec_calloc(1, sizeof(ServerAccountHeader));
    memcpy(hdr->magic, SERVER_ACCOUNT_FILE_MAGIC, strlen(SERVER_ACCOUNT_FILE_MAGIC));
    hdr->version = SERVER_ACCOUNT_FILE_VERSION;

    pthread_mutex_lock(&accounts_lock);

    hdr->num_accounts = num_accounts;

    int      email_space = (sizeof(uint16_t) + 25) * num_accounts;
    int      write_len   = sizeof(ServerAccountHeader);
    uint8_t *write_buf =
        ec_realloc(hdr, sizeof(ServerAccountHeader) + (sizeof(ServerAccount) * num_accounts) + email_space);
    hdr = (ServerAccountHeader *)write_buf;

    uint8_t *accounts_buf = write_buf + write_len;
    int      it           = 0;
    for (uint8_t *p = accounts_buf; p < accounts_buf + num_accounts * sizeof(ServerAccount); p += sizeof(ServerAccount))
        memcpy(p, &accounts[it++], sizeof(ServerAccount));

    write_len += sizeof(ServerAccount) * num_accounts;
    int written_email_len = 0;

    for (int i = 0; i < num_accounts; i++) {
        if (email_space < (int64_t)(sizeof(uint16_t) + accounts[i].email_len)) {
            // allocate space for ~ten more emails
            email_space += ((sizeof(uint16_t) + 25)) * 10;
            write_buf = ec_realloc(write_buf, write_len + email_space);
        }

        memcpy(write_buf + write_len + written_email_len, &accounts[i].email_len, sizeof(uint16_t));
        written_email_len += sizeof(uint16_t);

        memcpy(write_buf + write_len + written_email_len, accounts[i].email, accounts[i].email_len);
        written_email_len += accounts[i].email_len;
    }

    write_len += written_email_len;

    uint8_t *hash = sha_256_hash(write_buf + 10 + HASH_LEN, write_len - 10 - HASH_LEN);
    if (hash) {
        memcpy(hdr->hash, hash, HASH_LEN);
        free(hash);
    } else
        L_WARN("Failed to hash accounts data! Writing anyway with invalid hash");

    lock_file(ACCOUNTS_FILE); // not strictly necessary but good for future-proofing

    FILE *fp = fopen(ACCOUNTS_FILE, "wb");
    if (!fp) {
        pthread_mutex_unlock(&accounts_lock);
        unlock_file(ACCOUNTS_FILE);
        L_ERROR("Failed to open accounts file to save data!");
        free(write_buf);
        return -1;
    }

    fwrite(write_buf, 1, write_len, fp);
    plog(PLOG_DEBUG, "Wrote %d bytes to accounts.bin", write_len);
    fclose(fp);

    unlock_file(ACCOUNTS_FILE);

    free(write_buf);

    accounts_modified = 0;

    // don't unlock until here because we need to set accounts_modified still
    pthread_mutex_unlock(&accounts_lock);

    return 0; // success
}

static uint32_t get_next_user_id() {
    uint32_t id = 0;

    pthread_mutex_lock(&accounts_lock);
    for (int i = 0; i < num_accounts; i++)
        id = MAX(id, accounts[i].user_id);
    pthread_mutex_unlock(&accounts_lock);

    return ++id;
}

static uint32_t get_uid(char *email) {
    pthread_mutex_lock(&accounts_lock);
    for (int i = 0; i < num_accounts; i++) {
        if (!strcmp(accounts[i].email, email)) {
            uint32_t uid = accounts[i].user_id;
            pthread_mutex_unlock(&accounts_lock);
            return uid;
        }
    }
    pthread_mutex_unlock(&accounts_lock);

    return 0;
}

// TODO: possible ddos point (one client can AUTH many times and cause OOM)
// adds new token and returns base64-encoded version
static char *assign_token(uint32_t user_id) {

    pthread_mutex_lock(&tokens_lock);

    num_tokens++;
    tokens = (num_tokens - 1) ? ec_realloc(tokens, sizeof(AuthToken) * num_tokens) : ec_malloc(sizeof(AuthToken));

    tokens[num_tokens - 1].user_id     = user_id;
    tokens[num_tokens - 1].expire_time = time(NULL) + 36 * 60 * 60; // 36 hours
    randombytes_buf(tokens[num_tokens - 1].token, TOKEN_LEN);

    tokens_modified = 1;

    char *token_b64 = b64_encode(tokens[num_tokens - 1].token, TOKEN_LEN);

    pthread_mutex_unlock(&tokens_lock);

    return token_b64;
}

// returns reponse with err set on error, NULL on success
static cJSON *check_raw_token(char *email, uint8_t *token) {

    if (!email || !token)
        return server_error(E_INTERNALERR, "Missing email/token");

    uint32_t user_id = get_uid(email);

    if (user_id <= 0)
        return server_error(E_NOACCOUNT, "Failed to check token: invalid email");

    int error = 0;

    pthread_mutex_lock(&tokens_lock);

    for (int i = 0; i < num_tokens; i++) {
        if (tokens[i].user_id == user_id && !memcmp(token, tokens[i].token, TOKEN_LEN)) {
            if ((time_t)tokens[i].expire_time > time(NULL)) {
                error = 0;
                goto found_valid_token;
            } else {
                // collision chance is negligible in randomized 256-bit space; just return error
                error = E_EXPIREDTOKEN;
                break;
            }
        }
    }

    if (!error) {
        pthread_mutex_unlock(&tokens_lock);
        return server_error(E_INVALIDTOKEN, "Token incorrect/not found for provided id");
    }

found_valid_token:

    pthread_mutex_unlock(&tokens_lock);

    if (error)
        return server_error(error, "Token expired");
    return NULL;
}

static cJSON *check_token(cJSON *request) {

    cJSON *email_obj = cJSON_GetObjectItem(request, "email");
    cJSON *token_obj = cJSON_GetObjectItem(request, "token");

    if (!email_obj || !cJSON_IsString(email_obj))
        return server_error(E_BADREQ, "Missing email!");

    if (!token_obj || !cJSON_IsString(token_obj))
        return server_error(E_BADREQ, "Missing token!");

    int      token_len;
    uint8_t *token = b64_decode(cJSON_GetStringValue(token_obj), &token_len);
    if (!token || token_len != TOKEN_LEN)
        return server_error(E_BADTOKEN, "Failed to decode base64 token");

    cJSON *ret = check_raw_token(cJSON_GetStringValue(email_obj), token);
    free(token);
    return ret;
}

static void clean_tokens() {

    pthread_mutex_lock(&tokens_lock);

    for (int i = 0; i < num_tokens; i++) {
        if ((time_t)tokens[i].expire_time < time(NULL)) {
            tokens_modified = 1;
            num_tokens--;
            if (num_tokens == 0) {
                free(tokens);
                tokens = NULL;
            } else {
                for (int j = i; j < num_tokens; j++)
                    tokens[j] = tokens[j + 1];
                tokens = ec_realloc(tokens, num_tokens * sizeof(AuthToken));
                i--;
            }
        }
    }

    pthread_mutex_unlock(&tokens_lock);
}

static int save_tokens() {

    if (!tokens_modified)
        return 0; // nothing to do

    TokenFileHeader *hdr = ec_calloc(1, sizeof(TokenFileHeader));
    memcpy(hdr->magic, TOKEN_FILE_MAGIC, strlen(TOKEN_FILE_MAGIC));
    hdr->version = TOKEN_FILE_VERSION;

    pthread_mutex_lock(&tokens_lock);

    hdr->num_tokens = num_tokens;

    int      write_len = sizeof(TokenFileHeader);
    uint8_t *write_buf = ec_realloc(hdr, sizeof(TokenFileHeader) + (sizeof(AuthToken) * num_tokens));

    hdr = (TokenFileHeader *)write_buf;

    uint8_t *tokens_buf = write_buf + write_len;
    int      it         = 0;
    for (uint8_t *p = tokens_buf; p < tokens_buf + num_tokens * sizeof(AuthToken); p += sizeof(AuthToken))
        memcpy(p, &tokens[it++], sizeof(AuthToken));

    write_len += sizeof(AuthToken) * num_tokens;

    uint8_t *hash = sha_256_hash(write_buf + 10 + HASH_LEN, write_len - 10 - HASH_LEN);
    if (hash) {
        memcpy(hdr->hash, hash, HASH_LEN);
        free(hash);
    } else
        L_WARN("Failed to hash tokens data! Writing anyway with invalid hash");

    lock_file(TOKENS_FILE);

    FILE *fp = fopen(TOKENS_FILE, "wb");
    if (!fp) {
        pthread_mutex_unlock(&tokens_lock);
        unlock_file(TOKENS_FILE);
        L_ERROR("Failed to open tokens file to save data!");
        free(write_buf);
        return -1;
    }

    fwrite(write_buf, 1, write_len, fp);
    plog(PLOG_DEBUG, "Wrote %d bytes to tokens.bin", write_len);
    fclose(fp);

    unlock_file(TOKENS_FILE);

    free(write_buf);

    tokens_modified = 0;

    pthread_mutex_unlock(&tokens_lock);

    return 0; // success
}

struct upload_status {
    const char *data;
    size_t      bytes_left;
};

static size_t libcurl_read_cb(char *buffer, size_t size, size_t nmemb, void *userp) {
    struct upload_status *ctx = (struct upload_status *)userp;
    size_t                max = size * nmemb;

    if (ctx->bytes_left == 0)
        return 0;

    size_t to_copy = ctx->bytes_left < max ? ctx->bytes_left : max;

    memcpy(buffer, ctx->data, to_copy);

    ctx->data += to_copy;
    ctx->bytes_left -= to_copy;

    return to_copy;
}

static int send_verification_email(const char *to, int code) {
    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;

    char url[256];

    if (strcmp(smtp_config->smtp_tls, "tls") == 0) {
        snprintf(url, sizeof(url), "smtps://%s:%d", smtp_config->smtp_host, smtp_config->smtp_port);
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    } else {
        snprintf(url, sizeof(url), "smtp://%s:%d", smtp_config->smtp_host, smtp_config->smtp_port);

        if (strcmp(smtp_config->smtp_tls, "starttls") == 0) {
            curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
        }
    }

    char message[512];
    snprintf(message, sizeof(message),
             "Subject: Your Password Manager verification code\r\n"
             "\r\n"
             "Your account creation code is %06d\r\n"
             "This code is sent to verify that you own the email address you entered when creating/updating your "
             "account.\r\n"
             "Do not share it with anyone, and only enter it in a trusted Password Manager client.\r\n"
             "If you did not request this code, you should take action to secure your account now.",
             code);

    struct upload_status upload_ctx = {.data = message, .bytes_left = strlen(message)};

    struct curl_slist *recipients = NULL;
    recipients                    = curl_slist_append(recipients, to);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, smtp_config->smtp_from);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    curl_easy_setopt(curl, CURLOPT_USERNAME, smtp_config->smtp_user);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, smtp_config->smtp_pass);

    curl_easy_setopt(curl, CURLOPT_READFUNCTION, libcurl_read_cb);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}

// TODO: check support for multiple clients on one ip with per-ip verification codes
typedef struct ThreadData {
    ExpectedData ed;
    uint8_t      sent_challenge[CHALLENGE_LEN];
    char        *ip;
    SSL         *ssl;
    uint8_t     *file_recv_buf;
    uint32_t     file_recv_len;
} ThreadData;

static cJSON *finish_create_account(char *email, int code, ServerAccount *new_acc);
static cJSON *finish_update_account(char *email, char *old_email, uint8_t *token, int code, ServerAccount *new_acc);

static cJSON *run_create_account(cJSON *request, ThreadData *tdata) {

    cJSON *email_obj          = cJSON_GetObjectItem(request, "email");
    cJSON *request_resend_obj = cJSON_GetObjectItem(request, "request_resend");
    cJSON *username_hash_obj  = cJSON_GetObjectItem(request, "username_hash");
    cJSON *password_hash_obj  = cJSON_GetObjectItem(request, "password_hash");
    cJSON *auth_pk_obj        = cJSON_GetObjectItem(request, "auth_pk");
    cJSON *auth_seed_id_obj   = cJSON_GetObjectItem(request, "auth_seed_id");
    cJSON *salt_obj           = cJSON_GetObjectItem(request, "salt");

    int email_ok  = email_obj && cJSON_IsString(email_obj);
    int resend_ok = request_resend_obj && cJSON_IsBool(request_resend_obj);
    int data_ok = username_hash_obj && cJSON_IsString(username_hash_obj) && password_hash_obj &&
                  cJSON_IsString(password_hash_obj) && auth_pk_obj && cJSON_IsString(auth_pk_obj) && auth_seed_id_obj &&
                  cJSON_IsString(auth_seed_id_obj) && strlen(auth_seed_id_obj->valuestring) == 16 && salt_obj &&
                  cJSON_IsString(salt_obj);

    if (!email_ok || !(resend_ok ^ data_ok)) {
        return server_error(
            E_BADREQ,
            "Missing/malformed fields in request! (expected email (str) & (request_resend "
            "(bool) ^ username_hash (str), password_hash (str), auth_pk (str), and auth_seed_id (16 hex bytes))");
    }

    char *email = cJSON_GetStringValue(email_obj);

    uint8_t *username_hash = NULL;
    uint8_t *password_hash = NULL;
    uint8_t *auth_pk       = NULL;
    uint64_t auth_seed_id  = 0;
    uint8_t *salt          = NULL;

    if (request_resend_obj && request_resend_obj->type == cJSON_True) {
        if (!smtp_enabled())
            return server_error(E_INTERNALERR,
                                "Failed to resend email: smtp not enabled. Contact server admins to fix");
        goto resend_email;
    }

    auth_seed_id = hex_to_u64(auth_seed_id_obj->valuestring);

    int uname_hash_len;
    int passwd_hash_len;
    int auth_pk_len;
    int salt_len;

    username_hash = b64_decode(cJSON_GetStringValue(username_hash_obj), &uname_hash_len);
    password_hash = b64_decode(cJSON_GetStringValue(password_hash_obj), &passwd_hash_len);
    auth_pk       = b64_decode(cJSON_GetStringValue(auth_pk_obj), &auth_pk_len);
    salt          = b64_decode(cJSON_GetStringValue(salt_obj), &salt_len);

    if (!username_hash || !password_hash || !auth_pk || auth_seed_id < 2 || !salt) {
        if (username_hash)
            free(username_hash);
        if (password_hash)
            free(password_hash);
        if (auth_pk)
            free(auth_pk);
        if (salt)
            free(salt);

        return server_error(E_INTERNALERR, "Failed to decode one or more base64 strings from request!");
    }

    if (uname_hash_len != UNAME_HASH_LEN || passwd_hash_len != PASSWD_HASH_LEN || auth_pk_len != AUTH_PK_LEN ||
        auth_seed_id < 2 || salt_len != SALT_LEN) {

        free(username_hash);
        free(password_hash);
        free(auth_pk);
        free(salt);

        char err_msg[200];
        sprintf(err_msg,
                "Invalid length for one or more base64 fields, or invalid auth_seed_id! (expected uname_hash_len == "
                "%d, passwd_hash_len == %d, auth_pk_len == %d, auth_seed_id < 2, and salt_len == %d)",
                UNAME_HASH_LEN, PASSWD_HASH_LEN, AUTH_PK_LEN, SALT_LEN);
        return server_error(E_BADREQ, err_msg);
    }

    pthread_mutex_lock(&accounts_lock);
    for (int i = 0; i < num_accounts; i++) {
        if (!strcmp(accounts[i].email, email)) {

            pthread_mutex_unlock(&accounts_lock);

            free(username_hash);
            free(password_hash);
            free(auth_pk);
            free(salt);

            return server_error(E_DUPEVAL, "Provided email already exists in accounts database!");
        }
    }

    pthread_mutex_unlock(&accounts_lock);

    wchar_t wemail[320];
    size_t  converted = mbstowcs(wemail, email, sizeof(wemail) / sizeof(wchar_t));

    if (converted == (size_t)-1 || converted >= 320) {

        free(username_hash);
        free(password_hash);
        free(auth_pk);
        free(salt);

        return server_error(E_INTERNALERR, "Failed to convert email to wchar to validate!");
    }

    valid_mail_t email_vld = validate_email(wemail);
    if (!email_vld.success) {

        free(username_hash);
        free(password_hash);
        free(auth_pk);
        free(salt);

        char lib_vld_msg[256];
        wcstombs(lib_vld_msg, email_vld.message, sizeof(lib_vld_msg));
        char msg[300];
        snprintf(msg, sizeof(msg), "Invalid email address: %s", lib_vld_msg);
        msg[strlen(msg) - 1] = 0; // remove '\n'

        return server_error(E_INVALIDEMAIL, msg);
    }

    if (smtp_enabled()) {

    resend_email:
        pthread_mutex_lock(&verification_codes_lock);

        int code = -1;
        for (int i = 0; i < num_outstanding_codes; i++) {
            // dump expired codes; note that if another thread runs this code, it
            // will force the client to call the full CREATEACCOUNT request again
            // if a resend was requested, instead of just setting the resend flag.
            if ((time_t)verification_codes[i].expire_time < time(NULL)) {
                if ((!username_hash || !password_hash || !auth_pk) &&
                    !strcmp(email, verification_codes[i].new_acc->email)) {
                    verification_codes[i].code        = gen_verification_code();
                    verification_codes[i].expire_time = time(NULL) + (60 * 60);

                    code = i;
                } else {
                    free(verification_codes[i].new_acc->email);
                    free(verification_codes[i].new_acc);
                    if (verification_codes[i].request_ip_src)
                        free(verification_codes[i].request_ip_src);
                    num_outstanding_codes--;
                    for (int j = i; j < num_outstanding_codes; j++)
                        verification_codes[j] = verification_codes[j + 1];
                    if (num_outstanding_codes == 0) {
                        free(verification_codes);
                        verification_codes = NULL;
                    } else
                        verification_codes =
                            ec_realloc(verification_codes, num_outstanding_codes * sizeof(EmailVerificationCode));
                    i--;
                }
                continue;
            }
            if (!strcmp(verification_codes[i].new_acc->email, email))
                code = i;
        }

        int code_idx = -1;

        if (code >= 0)
            code = verification_codes[code].code;
        else {

            // no code to resend
            if (!username_hash || !password_hash || !auth_pk || !salt || !auth_seed_id) {
                tdata->ed = D_NONE;
                return server_error(E_NOCODEFOUND,
                                    "Failed to find code to resend! Please resend full CREATEACCOUNT request");
            }

            if (verification_codes)
                verification_codes =
                    ec_realloc(verification_codes, ++num_outstanding_codes * sizeof(EmailVerificationCode));
            else
                verification_codes = ec_calloc((num_outstanding_codes = 1), sizeof(EmailVerificationCode));

            code_idx = num_outstanding_codes - 1;

            verification_codes[code_idx].new_acc          = ec_malloc(sizeof(ServerAccount));
            verification_codes[code_idx].new_acc->user_id = 0; // NULL (tbd on actual registration)
            memcpy(verification_codes[code_idx].new_acc->uname_hash, username_hash, UNAME_HASH_LEN);
            memcpy(verification_codes[code_idx].new_acc->passwd_hash, password_hash, PASSWD_HASH_LEN);
            memcpy(verification_codes[code_idx].new_acc->auth_pk, auth_pk, AUTH_PK_LEN);
            memcpy(verification_codes[code_idx].new_acc->salt, salt, SALT_LEN);
            verification_codes[code_idx].new_acc->auth_seed_id  = auth_seed_id;
            verification_codes[code_idx].new_acc->last_modified = time(NULL);
            verification_codes[code_idx].new_acc->email_len     = strlen(email);
            verification_codes[code_idx].new_acc->email         = strdup(email);

            free(username_hash);
            free(password_hash);
            free(auth_pk);
            free(salt);

            code = gen_verification_code();

            verification_codes[code_idx].code           = code;
            verification_codes[code_idx].expire_time    = time(NULL) + 60 * 60; // 1 hour;
            verification_codes[code_idx].request_ip_src = strdup(tdata->ip);
            verification_codes[code_idx].type           = D_CA_EMAIL_VERIFICATION_CODE;
        }

        if (send_verification_email(email, code) < 0) {
            if (code_idx >= 0) {
                free(verification_codes[code_idx].new_acc->email);
                free(verification_codes[code_idx].new_acc);
                if (verification_codes[code_idx].request_ip_src)
                    free(verification_codes[code_idx].request_ip_src);
                if (num_outstanding_codes == 1) {
                    free(verification_codes);
                    verification_codes = NULL;
                    num_outstanding_codes--;
                } else
                    verification_codes =
                        ec_realloc(verification_codes, --num_outstanding_codes * sizeof(EmailVerificationCode));
            }

            pthread_mutex_unlock(&verification_codes_lock);

            return server_error(E_INTERNALERR,
                                "Failed to send email with verification code! (invalid smtp server configuration; "
                                "contact server admins to fix)");
        }

        pthread_mutex_unlock(&verification_codes_lock);

        tdata->ed       = D_CA_EMAIL_VERIFICATION_CODE;
        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", DATA_WAIT);
        return response;
    } else {

        ServerAccount *new_acc = ec_malloc(sizeof(ServerAccount));
        new_acc->user_id       = 0; // tbd
        memcpy(new_acc->uname_hash, username_hash, UNAME_HASH_LEN);
        memcpy(new_acc->passwd_hash, password_hash, PASSWD_HASH_LEN);
        memcpy(new_acc->auth_pk, auth_pk, AUTH_PK_LEN);
        memcpy(new_acc->salt, salt, SALT_LEN);
        new_acc->last_modified = time(NULL);
        new_acc->auth_seed_id  = auth_seed_id;
        new_acc->email_len     = strlen(email);
        new_acc->email         = strdup(email);

        free(username_hash);
        free(password_hash);
        free(auth_pk);
        free(salt);

        return finish_create_account(email, -1, new_acc); // -1 = no code required
    }
}

static cJSON *finish_create_account(char *email, int code, ServerAccount *new_acc) {

    // new_acc only set if no code is required (-1), email is required either way
    if ((code >= 0 && new_acc) || !email) {

        if (new_acc) {
            free(new_acc->email);
            free(new_acc);
        }

        return server_error(E_INTERNALERR, "Invalid data passed to finish_create_account! (expected either code OR "
                                           "new_acc struct, as well as valid email pointer)");
    }

    if (code >= 0) { // verify code

        pthread_mutex_lock(&verification_codes_lock);

        for (int i = 0; i < num_outstanding_codes; i++) {
            if (!strcmp(email, verification_codes[i].new_acc->email)) {
                if (code != verification_codes[i].code) {
                    pthread_mutex_unlock(&verification_codes_lock);

                    return server_error(E_INVALIDCODE, "Incorrect verification code for provided email");
                } else if ((time_t)verification_codes[i].expire_time < time(NULL)) {
                    pthread_mutex_unlock(&verification_codes_lock);

                    return server_error(E_EXPIREDCODE,
                                        "Verification code expired; try CREATEACCOUNT <email> request_resend=true");
                }

                new_acc = verification_codes[i].new_acc; // now owned by this function
                if (verification_codes[i].request_ip_src)
                    free(verification_codes[i].request_ip_src);

                num_outstanding_codes--;
                for (int j = i; j < num_outstanding_codes; j++)
                    verification_codes[j] = verification_codes[j + 1];
                if (num_outstanding_codes == 0) {
                    free(verification_codes);
                    verification_codes = NULL;
                } else
                    verification_codes =
                        ec_realloc(verification_codes, num_outstanding_codes * sizeof(EmailVerificationCode));
            }
        }

        pthread_mutex_unlock(&verification_codes_lock);

        if (!new_acc)
            return server_error(E_INVALIDDATA, "Invalid email address (no associated outstanding verification code)");
    }

    new_acc->user_id = get_next_user_id();

    pthread_mutex_lock(&accounts_lock);

    num_accounts++;
    accounts = (num_accounts - 1) ? ec_realloc(accounts, sizeof(ServerAccount) * num_accounts)
                                  : ec_malloc(sizeof(ServerAccount));

    accounts_modified = 1;

    // transfers ownership of char *email to accounts array
    accounts[num_accounts - 1] = *new_acc;

    pthread_mutex_unlock(&accounts_lock);

    char *token_b64 = assign_token(new_acc->user_id);

    if (!token_b64) {
        free(new_acc);
        return server_error(E_INTERNALERR, "Failed to generate token/encode it as base64! Your account has been "
                                           "successfully created, but no token could be returned.");
    }

    char timestamp_str[17];
    u64_to_hex(new_acc->last_modified, timestamp_str, sizeof(timestamp_str));
    free(new_acc);

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    cJSON_AddStringToObject(response, "token", token_b64);
    cJSON_AddStringToObject(response, "last_modified", timestamp_str); // tell client what time to expect
    free(token_b64);
    return response;
}

static cJSON *run_update_account(cJSON *request, ThreadData *tdata) {

    cJSON *token_check = check_token(request);
    if (token_check)
        return token_check;

    // safe because token_check asserts valid email
    char    *email = cJSON_GetStringValue(cJSON_GetObjectItem(request, "email"));
    uint32_t uid   = get_uid(email);
    if (!uid)
        return server_error(E_NOACCOUNT, "Failed to get uid from email!");

    cJSON *request_resend_obj    = cJSON_GetObjectItem(request, "request_resend");
    cJSON *new_email_obj         = cJSON_GetObjectItem(request, "new_email");
    cJSON *new_username_hash_obj = cJSON_GetObjectItem(request, "new_username_hash");
    cJSON *new_password_hash_obj = cJSON_GetObjectItem(request, "new_password_hash");
    cJSON *new_auth_pk_obj       = cJSON_GetObjectItem(request, "new_auth_pk");
    cJSON *new_auth_seed_id_obj  = cJSON_GetObjectItem(request, "new_auth_seed_id");
    cJSON *new_salt_obj          = cJSON_GetObjectItem(request, "new_salt");

    int has_update_data =
        (new_username_hash_obj || new_password_hash_obj || new_auth_pk_obj || new_auth_seed_id_obj || new_salt_obj);

    if (request_resend_obj && !cJSON_IsBool(request_resend_obj))
        return server_error(E_BADREQ, "Invalid data type for request_resend! (expected bool)");

    if (request_resend_obj && !smtp_enabled())
        return server_error(E_BADREQ, "SMTP verification not enabled!");

    if (request_resend_obj && has_update_data)
        return server_error(E_BADREQ, "If request_resend is set, only email, token, and new_email should be sent!");

    char *new_email = NULL; // owned by cJSON
    if (new_email_obj) {
        if (!cJSON_IsString(new_email_obj))
            return server_error(E_BADREQ, "Invalid type for new_email! (expected string)");

        new_email = cJSON_GetStringValue(new_email_obj);
    }

    ServerAccount *new_acc = NULL; // declare here to fix warnings

    int resend = 0;
    if (request_resend_obj && request_resend_obj->type == cJSON_True) {

        if (!new_email)
            return server_error(E_BADREQ, "Missing field 'new_email'!");

        resend = 1;
        goto resend_update_code;
    }

    if (!new_auth_pk_obj || !cJSON_IsString(new_auth_pk_obj) || !new_auth_seed_id_obj ||
        !cJSON_IsString(new_auth_seed_id_obj))
        return server_error(E_BADREQ, "You must update auth_pk on every account update");

    uint64_t new_auth_seed_id = hex_to_u64(new_auth_seed_id_obj->valuestring);
    if (new_auth_seed_id < 2)
        return server_error(E_BADREQ, "Invalid auth_seed_id (must be > 1)");

    int      auth_pk_len;
    uint8_t *new_auth_pk = b64_decode(cJSON_GetStringValue(new_auth_pk_obj), &auth_pk_len);
    if (!new_auth_pk || auth_pk_len != AUTH_PK_LEN) {
        if (new_auth_pk)
            free(new_auth_pk);

        return server_error(E_INTERNALERR, "Failed to decode base64 auth_pk/invalid length");
    }

    uint8_t *new_username_hash = NULL;
    uint8_t *new_password_hash = NULL;
    uint8_t *new_salt          = NULL;

    if (new_username_hash_obj) {
        if (!cJSON_IsString(new_username_hash_obj)) {
            free(new_auth_pk);
            return server_error(E_BADREQ, "Invalid type for new_username_hash! (expected string)");
        }

        int username_hash_len;
        new_username_hash = b64_decode(cJSON_GetStringValue(new_username_hash_obj), &username_hash_len);

        if (!new_username_hash || username_hash_len != UNAME_HASH_LEN) {
            if (new_username_hash)
                free(new_username_hash);
            free(new_auth_pk);
            return server_error(E_INTERNALERR, "Failed to decode base64 new_username_hash/invalid length");
        }
    }

    if (new_password_hash_obj) {
        if (!cJSON_IsString(new_password_hash_obj)) {
            free(new_auth_pk);
            free(new_username_hash);
            return server_error(E_BADREQ, "Invalid type for new_password_hash! (expected string)");
        }

        int password_hash_len;
        new_password_hash = b64_decode(cJSON_GetStringValue(new_password_hash_obj), &password_hash_len);

        if (!new_password_hash || password_hash_len != PASSWD_HASH_LEN) {
            if (new_username_hash)
                free(new_username_hash);
            free(new_auth_pk);
            if (new_password_hash)
                free(new_password_hash);
            return server_error(E_INTERNALERR, "Failed to decode base64 new_password_hash/invalid length");
        }
    }

    if (new_salt) {
        if (!cJSON_IsString(new_salt_obj)) {
            free(new_auth_pk);
            free(new_username_hash);
            free(new_password_hash);
            return server_error(E_BADREQ, "Invalid type for new_salt! (expected string)");
        }

        int salt_len;
        new_salt = b64_decode(new_salt_obj->valuestring, &salt_len);

        if (!new_salt || salt_len != SALT_LEN) {
            if (new_salt)
                free(new_salt);
            free(new_auth_pk);
            if (new_username_hash)
                free(new_username_hash);
            if (new_password_hash)
                free(new_password_hash);
            return server_error(E_INTERNALERR, "Failed to decode base64 new_salt/invalid length");
        }
    }

    new_acc = ec_calloc(1, sizeof(ServerAccount));

    pthread_mutex_lock(&accounts_lock);

    for (int i = 0; i < num_accounts; i++) {
        if (accounts[i].user_id == uid) { // copy account
            *new_acc       = accounts[i];
            new_acc->email = strdup(accounts[i].email);
            break;
        }
    }

    pthread_mutex_unlock(&accounts_lock);

    if (!new_acc->user_id) {
        free(new_acc);
        if (new_username_hash)
            free(new_username_hash);
        if (new_password_hash)
            free(new_password_hash);
        free(new_auth_pk);
        return server_error(E_NOACCOUNT, "Failed to retrieve account from uid! Please try again");
    }

    if (!memcmp(new_auth_pk, new_acc->auth_pk, AUTH_PK_LEN) || new_acc->auth_seed_id == new_auth_seed_id) {
        free(new_acc->email);
        free(new_acc);
        if (new_username_hash)
            free(new_username_hash);
        if (new_password_hash)
            free(new_password_hash);
        free(new_auth_pk);
        return server_error(
            E_BADREQ, "new auth_pk & auth_seed_id must be different from current auth_pk & auth_seed_id! (nice try)");
    }

    new_acc->auth_seed_id = new_auth_seed_id;
    memcpy(new_acc->auth_pk, new_auth_pk, AUTH_PK_LEN);
    free(new_auth_pk);
    if (new_username_hash) {
        memcpy(new_acc->uname_hash, new_username_hash, UNAME_HASH_LEN);
        free(new_username_hash);
    }
    if (new_password_hash) {
        memcpy(new_acc->passwd_hash, new_password_hash, PASSWD_HASH_LEN);
        free(new_password_hash);
    }
    if (new_salt) {
        memcpy(new_acc->salt, new_salt, SALT_LEN);
        free(new_salt);
    }

    new_acc->last_modified = time(NULL);

    if (new_email && strcmp(new_email, new_acc->email)) {

        free(new_acc->email);
        new_acc->email = strdup(new_email);

        pthread_mutex_lock(&accounts_lock);
        for (int i = 0; i < num_accounts; i++) {
            if (!strcmp(accounts[i].email, new_email)) {

                pthread_mutex_unlock(&accounts_lock);

                free(new_acc->email);
                free(new_acc);

                return server_error(E_DUPEVAL, "Provided email already exists in accounts database!");
            }
        }

        pthread_mutex_unlock(&accounts_lock);

        wchar_t wemail[320];
        size_t  converted = mbstowcs(wemail, new_email, sizeof(wemail) / sizeof(wchar_t));

        if (converted == (size_t)-1 || converted >= 320) {

            free(new_acc->email);
            free(new_acc);

            return server_error(E_INTERNALERR, "Failed to convert new email to wchar to validate!");
        }

        valid_mail_t email_vld = validate_email(wemail);
        if (!email_vld.success) {

            free(new_acc->email);
            free(new_acc);

            char lib_vld_msg[256];
            wcstombs(lib_vld_msg, email_vld.message, sizeof(lib_vld_msg));
            char msg[300];
            snprintf(msg, sizeof(msg), "Invalid email address: %s", lib_vld_msg);
            msg[strlen(msg) - 1] = 0; // remove '\n'

            return server_error(E_INVALIDEMAIL, msg);
        }

        if (smtp_enabled()) {

        resend_update_code:

            pthread_mutex_lock(&verification_codes_lock);

            int code = -1;
            for (int i = 0; i < num_outstanding_codes; i++) {
                if ((time_t)verification_codes[i].expire_time < time(NULL)) {
                    if (resend && !strcmp(new_email, verification_codes[i].new_acc->email)) {
                        verification_codes[i].code        = gen_verification_code();
                        verification_codes[i].expire_time = time(NULL) + (60 * 60);

                        code = i;
                    } else {
                        free(verification_codes[i].new_acc->email);
                        free(verification_codes[i].new_acc);
                        if (verification_codes[i].request_ip_src)
                            free(verification_codes[i].request_ip_src);
                        num_outstanding_codes--;
                        for (int j = i; j < num_outstanding_codes; j++)
                            verification_codes[j] = verification_codes[j + 1];
                        if (num_outstanding_codes == 0) {
                            free(verification_codes);
                            verification_codes = NULL;
                        } else
                            verification_codes =
                                ec_realloc(verification_codes, num_outstanding_codes * sizeof(EmailVerificationCode));
                        i--;
                    }
                    continue;
                }
                if (!strcmp(verification_codes[i].new_acc->email, new_email))
                    code = i;
            }

            int code_idx = -1;

            if (code >= 0)
                code = verification_codes[code].code;
            else {

                // no code to resend
                if (resend) {
                    tdata->ed = D_NONE;
                    return server_error(E_NOCODEFOUND,
                                        "Failed to find code to resend! Please retry full UPDATEACCOUNT request");
                }

                if (verification_codes)
                    verification_codes =
                        ec_realloc(verification_codes, ++num_outstanding_codes * sizeof(EmailVerificationCode));
                else
                    verification_codes = ec_calloc((num_outstanding_codes = 1), sizeof(EmailVerificationCode));

                code_idx = num_outstanding_codes - 1;

                verification_codes[code_idx].new_acc = new_acc;

                code = gen_verification_code();

                verification_codes[code_idx].code           = code;
                verification_codes[code_idx].expire_time    = time(NULL) + 60 * 60; // 1 hour;
                verification_codes[code_idx].request_ip_src = strdup(tdata->ip);
                verification_codes[code_idx].type           = D_UA_EMAIL_VERIFICATION_CODE;
            }

            if (send_verification_email(email, code) < 0) {
                if (code_idx >= 0) {
                    free(verification_codes[code_idx].new_acc->email);
                    free(verification_codes[code_idx].new_acc);
                    free(verification_codes[code_idx].request_ip_src);
                    if (num_outstanding_codes == 1) {
                        free(verification_codes);
                        verification_codes = NULL;
                        num_outstanding_codes--;
                    } else
                        verification_codes =
                            ec_realloc(verification_codes, --num_outstanding_codes * sizeof(EmailVerificationCode));
                }

                pthread_mutex_unlock(&verification_codes_lock);

                return server_error(E_INTERNALERR,
                                    "Failed to send email with verification code! (invalid smtp server configuration; "
                                    "contact server admins to fix)");
            }

            pthread_mutex_unlock(&verification_codes_lock);

            tdata->ed = D_UA_EMAIL_VERIFICATION_CODE;

            cJSON *response = cJSON_CreateObject();
            cJSON_AddNumberToObject(response, "code", DATA_WAIT);
            return response;
        } else {

            int      token_len;
            uint8_t *token = b64_decode(cJSON_GetStringValue(cJSON_GetObjectItem(request, "token")), &token_len);
            if (!token || token_len != TOKEN_LEN) {
                free(new_acc->email);
                free(new_acc);
                if (token)
                    free(token);
                return server_error(E_BADTOKEN, "Failed to decode base64 token! (OOM/invalid length)");
            }

            return finish_update_account(new_email, email, token, -1, new_acc); // -1 = no code required
        }

    } else {

        int64_t success = 0; // will hold last_modified on success

        pthread_mutex_lock(&accounts_lock);

        for (int i = 0; i < num_accounts; i++) {
            if (accounts[i].user_id == uid) {
                accounts_modified = 1;
                free(accounts[i].email);
                accounts[i] = *new_acc;
                free(new_acc);
                success = accounts[i].last_modified;
            }
        }

        pthread_mutex_unlock(&accounts_lock);

        if (!success) {
            free(new_acc->email);
            free(new_acc);
            return server_error(E_NOACCOUNT, "Failed to find account to update from uid! (changed by another thread)");
        }

        char timestamp_str[17];
        u64_to_hex(success, timestamp_str, sizeof(timestamp_str));

        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
        cJSON_AddStringToObject(response, "last_modified", timestamp_str);
        return response;
    }
}

static cJSON *finish_update_account(char *email, char *old_email, uint8_t *token, int code, ServerAccount *new_acc) {
    cJSON *token_check = check_raw_token(old_email, token);
    if (token_check)
        return token_check;

    if ((code >= 0 && new_acc) || !email) {

        if (new_acc) {
            free(new_acc->email);
            free(new_acc);
        }

        return server_error(E_INTERNALERR, "Invalid data passed to finish_update_account! (expected either code OR "
                                           "new_acc struct, as well as valid email pointer)");
    }

    if (code >= 0) { // verify code

        pthread_mutex_lock(&verification_codes_lock);

        for (int i = 0; i < num_outstanding_codes; i++) {
            if (!strcmp(email, verification_codes[i].new_acc->email)) {
                if (code != verification_codes[i].code) {
                    pthread_mutex_unlock(&verification_codes_lock);

                    return server_error(E_INVALIDCODE, "Incorrect verification code for provided email");
                } else if ((time_t)verification_codes[i].expire_time < time(NULL)) {
                    pthread_mutex_unlock(&verification_codes_lock);

                    return server_error(
                        E_EXPIREDCODE,
                        "Verification code expired; try UPDATEACCOUNT <email> <token> <new_email> request_resend=true");
                }

                new_acc = verification_codes[i].new_acc; // now owned by this function
                if (verification_codes[i].request_ip_src)
                    free(verification_codes[i].request_ip_src);

                num_outstanding_codes--;
                for (int j = i; j < num_outstanding_codes; j++)
                    verification_codes[j] = verification_codes[j + 1];
                if (num_outstanding_codes == 0) {
                    free(verification_codes);
                    verification_codes = NULL;
                } else
                    verification_codes =
                        ec_realloc(verification_codes, num_outstanding_codes * sizeof(EmailVerificationCode));
            }
        }

        pthread_mutex_unlock(&verification_codes_lock);

        if (!new_acc)
            return server_error(E_INVALIDDATA, "Invalid email address (no associated outstanding verification code)");
    }

    uint32_t uid = get_uid(old_email);
    if (!uid) {
        free(new_acc->email);
        free(new_acc);

        return server_error(E_NOACCOUNT, "Failed to fetch uid from old email!");
    }

    int64_t success = 0;

    pthread_mutex_lock(&accounts_lock);

    for (int i = 0; i < num_accounts; i++) {
        if (accounts[i].user_id == uid) {
            accounts_modified = 1;
            free(accounts[i].email);
            accounts[i] = *new_acc;
            free(new_acc);
            success = accounts[i].last_modified;
        }
    }

    pthread_mutex_unlock(&accounts_lock);

    if (!success) {
        free(new_acc->email);
        free(new_acc);
        return server_error(E_INTERNALERR, "Failed to find account to update from uid! (changed by another thread)");
    }

    // rename vault

    char *old_vault_path = ec_malloc(strlen(VAULTS_DIR) + HASH_LEN * 2 + strlen(".pwmngr") + 1);
    char *new_vault_path = ec_malloc(strlen(VAULTS_DIR) + HASH_LEN * 2 + strlen(".pwmngr") + 1);
    char *old_email_hash = hash_email(old_email);
    char *new_email_hash = hash_email(email);
    sprintf(old_vault_path, "%s%s.pwmngr", VAULTS_DIR, old_email_hash);
    sprintf(new_vault_path, "%s%s.pwmngr", VAULTS_DIR, new_email_hash);
    free(old_email_hash);
    free(new_email_hash);

    lock_file(old_vault_path);
    lock_file(new_vault_path);

    FILE *fp = fopen(new_vault_path, "rb");
    if (fp) {
        fclose(fp);
        unlock_file(old_vault_path);
        unlock_file(new_vault_path);
        free(old_vault_path);
        free(new_vault_path);
        L_ERROR("New vault path already exists! (bug/thread issue)");
        return server_error(E_INTERNALERR, "Failed to rename user vault! (new vault already exists)");
    }

    fp = fopen(old_vault_path, "rb");
    if (fp) {

        fclose(fp);
        unlock_file(old_vault_path);
        unlock_file(new_vault_path);

        if (rename(old_vault_path, new_vault_path)) {
            free(old_vault_path);
            free(new_vault_path);
            L_ERROR("Failed to rename vault!");
            return server_error(E_INTERNALERR, "Failed to rename user vault!");
        }

        free(old_vault_path);
        free(new_vault_path);

    } else { // vault not created yet; do nothing
        unlock_file(old_vault_path);
        unlock_file(new_vault_path);
        free(old_vault_path);
        free(new_vault_path);
    }

    char timestamp_str[17];
    u64_to_hex(success, timestamp_str, sizeof(timestamp_str));

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    cJSON_AddStringToObject(response, "last_modified", timestamp_str);
    return response;
}

// client can call CREATEACCOUNT again if it wants to support non-permanent deletes
static cJSON *run_delete_account(cJSON *request) {

    cJSON *token_check = check_token(request);
    if (token_check)
        return token_check;

    // token check asserts valid email
    char    *email = cJSON_GetStringValue(cJSON_GetObjectItem(request, "email"));
    uint32_t uid   = get_uid(email);
    if (!uid)
        return server_error(E_NOACCOUNT, "Failed to get uid from email! (modified by another thread)");

    int success = 0;

    pthread_mutex_lock(&accounts_lock);

    for (int i = 0; i < num_accounts; i++) {
        if (accounts[i].user_id == uid) {
            accounts_modified = 1;
            free(accounts[i].email);
            num_accounts--;
            for (int j = i; j < num_accounts; j++)
                accounts[j] = accounts[j + 1];
            if (!num_accounts) {
                free(accounts);
                accounts = NULL;
            } else
                accounts = ec_realloc(accounts, num_accounts * sizeof(ServerAccount));
            success = 1;
        }
    }

    pthread_mutex_unlock(&accounts_lock);

    // very unlikely but possible (assuming malicious scheduling + requests)
    if (!success)
        return server_error(E_NOACCOUNT, "Failed to find account from uid! (modified by another thread)");

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    return response;
}

static cJSON *run_import_account(cJSON *request) {

    cJSON *token_check = check_token(request);
    if (token_check)
        return token_check;

    cJSON *last_known_timestamp_obj = cJSON_GetObjectItem(request, "last_known_timestamp");
    if (!last_known_timestamp_obj || !cJSON_IsString(last_known_timestamp_obj) ||
        strlen(last_known_timestamp_obj->valuestring) != 16)
        return server_error(E_BADREQ, "Missing/invalid field 'last_known_timestamp'!");

    time_t client_timestamp = (time_t)hex_to_u64(last_known_timestamp_obj->valuestring);

    uint32_t uid = get_uid(cJSON_GetObjectItem(request, "email")->valuestring);

    ServerAccount *acc = ec_calloc(1, sizeof(ServerAccount));

    pthread_mutex_lock(&accounts_lock);

    for (int i = 0; i < num_accounts; i++) {
        if (accounts[i].user_id == uid) {
            *acc = accounts[i]; // ignore email; it isn't used
            break;
        }
    }

    pthread_mutex_unlock(&accounts_lock);

    if (!acc->user_id) {
        free(acc);
        return server_error(E_NOACCOUNT, "No account found for provided email!");
    }

    if (acc->last_modified == client_timestamp) {
        free(acc);
        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", E_CLIENTUPTODATE);
        return response;
    }

    char *uname_hash_b64  = b64_encode(acc->uname_hash, UNAME_HASH_LEN);
    char *passwd_hash_b64 = b64_encode(acc->passwd_hash, PASSWD_HASH_LEN);
    char *auth_pk_b64     = b64_encode(acc->auth_pk, AUTH_PK_LEN);
    char *salt_b64        = b64_encode(acc->salt, SALT_LEN);
    if (!uname_hash_b64 || !passwd_hash_b64 || !auth_pk_b64 || !salt_b64) {
        free(acc);
        if (uname_hash_b64)
            free(uname_hash_b64);
        if (passwd_hash_b64)
            free(passwd_hash_b64);
        if (auth_pk_b64)
            free(auth_pk_b64);
        if (salt_b64)
            free(salt_b64);

        return server_error(E_INTERNALERR, "Failed to encode one or more fields as base64! (OOM/bad data)");
    }

    char auth_seed_id_str[17];
    char last_modified_str[17];

    u64_to_hex(acc->auth_seed_id, auth_seed_id_str, sizeof(auth_seed_id_str));
    u64_to_hex(acc->last_modified, last_modified_str, sizeof(last_modified_str));

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    cJSON_AddStringToObject(response, "uname_hash", uname_hash_b64);
    cJSON_AddStringToObject(response, "passwd_hash", passwd_hash_b64);
    cJSON_AddStringToObject(response, "auth_pk", auth_pk_b64);
    cJSON_AddStringToObject(response, "auth_seed_id", auth_seed_id_str);
    cJSON_AddStringToObject(response, "salt", salt_b64);
    cJSON_AddStringToObject(response, "last_modified", last_modified_str);
    free(acc);
    return response;
}

static cJSON *run_auth(cJSON *request, ThreadData *td) {

    cJSON *email_obj = cJSON_GetObjectItem(request, "email");

    if (!email_obj || !cJSON_IsString(email_obj))
        return server_error(E_BADREQ, "No email provided!");

    uint32_t uid = get_uid(cJSON_GetStringValue(email_obj));
    if (!uid)
        return server_error(E_NOACCOUNT, "No account found for provided email!");

    uint8_t challenge[CHALLENGE_LEN];
    randombytes_buf(challenge, CHALLENGE_LEN);
    char *challenge_b64 = b64_encode(challenge, CHALLENGE_LEN);
    if (!challenge_b64)
        return server_error(E_INTERNALERR, "Failed to encode challenge as base64 string; please try again");

    td->ed = D_CHALLENGE_RESPONSE;
    memcpy(td->sent_challenge, challenge, CHALLENGE_LEN);
    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", DATA_WAIT);
    cJSON_AddStringToObject(response, "challenge", challenge_b64);
    free(challenge_b64);
    return response;
}

static cJSON *finish_auth(uint32_t uid, uint8_t *signature, ThreadData *td) {

    uint8_t *auth_pk = NULL;

    pthread_mutex_lock(&accounts_lock);
    for (int i = 0; i < num_accounts; i++)
        if (accounts[i].user_id == uid)
            auth_pk = accounts[i].auth_pk;
    pthread_mutex_unlock(&accounts_lock);

    if (!auth_pk) {
        td->ed = D_NONE;
        return server_error(E_INTERNALERR, "Failed to fetch auth_pk from account by uid; please try again");
    }

    if (crypto_sign_verify_detached(signature, td->sent_challenge, CHALLENGE_LEN, auth_pk)) {
        td->ed = D_NONE;
        return server_error(E_BADSIGNATURE, "Challenge verification failed: invalid signature");
    }

    char *token_b64 = assign_token(uid);

    if (!token_b64) {
        td->ed = D_NONE;
        return server_error(E_INTERNALERR, "Failed to assign token/convert it to base64; please try again");
    }

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    cJSON_AddStringToObject(response, "token", token_b64);
    free(token_b64);
    return response;
}

// invalidate all tokens for an account (but requires a token to run) - used to secure account after token leak
static cJSON *run_invalidate_tokens(cJSON *request) {

    cJSON *token_check = check_token(request);
    if (token_check)
        return token_check;

    uint32_t uid = get_uid(cJSON_GetObjectItem(request, "email")->valuestring);

    pthread_mutex_lock(&tokens_lock);

    int tok_start_num = num_tokens;

    for (int i = 0; i < num_tokens; i++) {
        if (tokens[i].user_id == uid) {
            tokens_modified = 1;
            num_tokens--;
            if (num_tokens == 0) {
                free(tokens);
                tokens = NULL;
            } else {
                for (int j = i; j < num_tokens; j++)
                    tokens[j] = tokens[j + 1];
                tokens = ec_realloc(tokens, num_tokens * sizeof(AuthToken));
                i--;
            }
        }
    }

    int num_tokens_removed = num_tokens - tok_start_num;

    pthread_mutex_unlock(&tokens_lock);

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    cJSON_AddNumberToObject(response, "tokens_removed", num_tokens_removed);
    return response;
}

// get data for key derivation (salt + auth_seed_id)
static cJSON *run_get_account_info(cJSON *request) {

    cJSON *email_obj = cJSON_GetObjectItem(request, "email");
    if (!email_obj || !cJSON_IsString(email_obj))
        return server_error(E_BADREQ, "Missing/invalid field 'email'! (expected string)");

    // can be set to 0 if the client is requesting this for the first time;
    // it's just meant to reduce client-side work where possible (same with IMPORTACCOUNT)
    cJSON *last_known_timestamp_obj = cJSON_GetObjectItem(request, "last_known_timestamp");
    if (!last_known_timestamp_obj || !cJSON_IsString(last_known_timestamp_obj) ||
        strlen(last_known_timestamp_obj->valuestring) != 16)
        return server_error(E_BADREQ, "Missing/invalid field 'last_known_timestamp'!");

    time_t client_timestamp = (time_t)hex_to_u64(last_known_timestamp_obj->valuestring);

    uint32_t uid = get_uid(email_obj->valuestring);
    if (!uid)
        return server_error(E_NOACCOUNT, "No account found for provided email!");

    int64_t  last_modified = 0;
    uint64_t auth_seed_id  = 0;
    uint8_t  salt[SALT_LEN];

    pthread_mutex_lock(&accounts_lock);

    for (int i = 0; i < num_accounts; i++) {
        if (accounts[i].user_id == uid) {
            last_modified = accounts[i].last_modified;
            auth_seed_id  = accounts[i].auth_seed_id;
            memcpy(salt, accounts[i].salt, SALT_LEN);
            break;
        }
    }

    pthread_mutex_unlock(&accounts_lock);

    if (!last_modified)
        return server_error(E_NOACCOUNT, "Failed to find account from uid! (modified by another thread)");

    if (last_modified == client_timestamp) {
        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", E_CLIENTUPTODATE);
        return response;
    }

    char *salt_b64 = b64_encode(salt, SALT_LEN);
    if (!salt_b64)
        return server_error(E_INTERNALERR, "Failed to encode salt as base64! (OOM)");

    // hex string because cJSON doesn't support uint64_t
    char auth_seed_id_str[17];
    char last_modified_str[17];

    u64_to_hex(auth_seed_id, auth_seed_id_str, sizeof(auth_seed_id_str));
    u64_to_hex(last_modified, last_modified_str, sizeof(last_modified_str));

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    cJSON_AddStringToObject(response, "auth_seed_id", auth_seed_id_str);
    cJSON_AddStringToObject(response, "salt", salt_b64);
    cJSON_AddStringToObject(response, "last_modified", last_modified_str);
    free(salt_b64);
    return response;
}

static cJSON *run_get_vault(cJSON *request, ThreadData *tdata,
                            void(send_packet)(SSL *ssl, const uint8_t *data, const uint16_t data_len)) {

    cJSON *token_check = check_token(request);
    if (token_check)
        return token_check;

    cJSON *force_obj = cJSON_GetObjectItem(request, "force");
    int    force     = 0;
    if (force_obj && cJSON_IsBool(force_obj) && force_obj->type == cJSON_True)
        force = 1;

    cJSON *timestamp_obj = cJSON_GetObjectItem(request, "last_known_timestamp");
    if (!timestamp_obj || !cJSON_IsString(timestamp_obj))
        return server_error(E_BADREQ, "Missing last_known_timestamp! (used to check if vault needs to be sent; "
                                      "expected string representation of hex time_t)");

    char *client_timestamp_str = timestamp_obj->valuestring;

    if (strlen(client_timestamp_str) != 16)
        return server_error(E_BADREQ, "Invalid timestamp string!");

    time_t client_timestamp = (time_t)hex_to_u64(client_timestamp_str);

    if (client_timestamp > time(NULL))
        return server_error(E_BADREQ, "Invalid timestamp! (time in the future)");

    char *vault_path = ec_malloc(strlen(VAULTS_DIR) + HASH_LEN * 2 + strlen(".pwmngr") + 1);
    char *email_hash = hash_email(cJSON_GetObjectItem(request, "email")->valuestring);
    sprintf(vault_path, "%s%s.pwmngr", VAULTS_DIR, email_hash);
    free(email_hash);

    lock_file(vault_path);

    FILE *fp = fopen(vault_path, "rb");
    if (!fp) {
        unlock_file(vault_path);
        free(vault_path);
        L_ERROR("Failed to open user vault!");
        return server_error(E_INTERNALERR, "Failed to open user vault! (vault does not exist)");
    }

    // TODO: read once instead of verifying then sending

    fseek(fp, 0, SEEK_END);
    long fsize           = ftell(fp);
    long remaining_bytes = fsize;
    fseek(fp, 0, SEEK_SET);

    if (fsize < (long)sizeof(VaultHeader)) {
        fclose(fp);
        unlock_file(vault_path);
        free(vault_path);

        return server_error(E_BADVAULT, "Vault to small to contain header!");
    }

    VaultHeader *hdr = ec_malloc(fsize);
    fread((uint8_t *)hdr, 1, fsize, fp); // read the whole file first, to verify hash
    fseek(fp, 0, SEEK_SET);

    if (memcmp(hdr->magic, V_MAGIC, 6)) {
        fclose(fp);
        unlock_file(vault_path);
        free(vault_path);
        free(hdr);

        return server_error(E_BADVAULT, "Invalid vault magic!");
    }

    if (hdr->version != V_VERSION) {
        fclose(fp);
        unlock_file(vault_path);
        free(vault_path);
        free(hdr);

        return server_error(E_BADVAULT, "Invalid vault version!");
    }

    uint8_t *hash = sha_256_hash((uint8_t *)hdr + 10 + HASH_LEN, fsize - 10 - HASH_LEN);
    if (!hash) {
        fclose(fp);
        unlock_file(vault_path);
        free(vault_path);
        free(hdr);

        return server_error(E_INTERNALERR, "Failed to hash vault data!");
    }

    if (memcmp(hash, hdr->hash, HASH_LEN)) {
        if (force)
            L_WARN("Vault has invalid hash, but force is set; sending anyway!");
        else {
            fclose(fp);
            unlock_file(vault_path);
            free(vault_path);
            free(hash);
            free(hdr);

            return server_error(E_BADVAULT, "Verification failed for vault: invalid hash!");
        }
    }

    free(hash);

    if ((time_t)hdr->timestamp < client_timestamp) {
        if (force)
            L_WARN("Client has newer vault than server, but force is set; sending anyway!");
        else {
            cJSON *response = cJSON_CreateObject();
            cJSON_AddNumberToObject(response, "code", E_VAULTUPTODATE);
            cJSON_AddBoolToObject(response, "client_has_newer_version", 1);

            fclose(fp);
            unlock_file(vault_path);
            free(vault_path);
            free(hdr);

            return response;
        }
    }

    free(hdr);

    while (remaining_bytes > 0) {

        uint16_t sent_bytes = MIN(remaining_bytes, VAULT_CHUNK_SIZE);
        uint8_t  buf[VAULT_CHUNK_SIZE + 4 + sizeof(uint16_t)];
        memcpy(buf, "DATA", 4);
        memcpy(buf + 4, (uint8_t *)&sent_bytes, sizeof(uint16_t));
        fread(buf + 4 + sizeof(uint16_t), 1, sent_bytes, fp);

        send_packet(tdata->ssl, buf, sent_bytes + 6);

        remaining_bytes -= sent_bytes;
    }

    fclose(fp);

    unlock_file(vault_path);
    free(vault_path);

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    cJSON_AddNumberToObject(response, "bytes_sent", (int)fsize);
    return response;
}

static cJSON *run_push_vault(cJSON *request, ThreadData *tdata) {

    cJSON *token_check = check_token(request);
    if (token_check)
        return token_check;

    cJSON *timestamp_obj = cJSON_GetObjectItem(request, "vault_timestamp");
    if (!timestamp_obj || !cJSON_IsString(timestamp_obj))
        return server_error(E_BADREQ, "Missing vault modification timestamp!");

    if (strlen(timestamp_obj->valuestring) != 16)
        return server_error(E_BADREQ, "Invalid timestamp string!");

    time_t client_timestamp = (time_t)hex_to_u64(timestamp_obj->valuestring);

    if (client_timestamp > time(NULL))
        return server_error(E_BADREQ, "Invalid timestamp! (time in the future)");

    char *vault_path = ec_malloc(strlen(VAULTS_DIR) + HASH_LEN * 2 + strlen(".pwmngr") + 1);
    char *email_hash = hash_email(cJSON_GetObjectItem(request, "email")->valuestring);
    sprintf(vault_path, "%s%s.pwmngr", VAULTS_DIR, email_hash);
    free(email_hash);
    lock_file(vault_path);
    FILE *fp = fopen(vault_path, "w");
    if (!fp) {
        unlock_file(vault_path);
        free(vault_path);
        L_ERROR("Failed to open/create user vault!");
        return server_error(E_INTERNALERR, "Failed to open/create user vault!");
    }
    fclose(fp);
    fp = fopen(vault_path, "rb");
    if (!fp) {
        unlock_file(vault_path);
        free(vault_path);
        L_ERROR("Failed to open user vault for reading!");
        return server_error(E_INTERNALERR, "Failed to open user vault for reading!");
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize >= (long)sizeof(VaultHeader)) {

        VaultHeader *hdr = ec_calloc(1, sizeof(VaultHeader));
        fread(hdr, 1, sizeof(VaultHeader), fp);

        if ((time_t)hdr->timestamp > client_timestamp) { // don't accept push if server has newer vault
            cJSON *response = cJSON_CreateObject();
            cJSON_AddNumberToObject(response, "code", E_VAULTUPTODATE);
            cJSON_AddBoolToObject(response, "server_has_newer_version", 1);

            fclose(fp);
            unlock_file(vault_path);
            free(vault_path);

            return response;
        }
    }

    fclose(fp);

    unlock_file(vault_path);
    free(vault_path);

    tdata->ed = D_PWMNGR_FILE_TRANSFER;

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", DATA_WAIT);
    return response;
}

void send_pwmngr_file_packet(SSL *ssl, const uint8_t *data, const uint16_t data_len) {
    if (SSL_write(ssl, data, data_len) <= 0) {
        openssl_log_errors();
        L_ERROR("TLS write error");
        return;
    }
}

// TODO: client could possibly swap to another account's email & token?
static cJSON *save_pwmngr_file(char *email, uint8_t *token, uint16_t data_len, uint8_t *fdata, ThreadData *tdata) {

    cJSON *token_check = check_raw_token(email, token);
    if (token_check)
        return token_check;

    if (data_len == 0) { // done; write to file

        tdata->ed = D_NONE;

        if (tdata->file_recv_len < sizeof(VaultHeader))
            return server_error(E_BADVAULT, "Received data length is less than sizeof(VaultHeader)");

        VaultHeader *hdr = (VaultHeader *)tdata->file_recv_buf;

        if (memcmp(hdr->magic, V_MAGIC, 6)) {
            free(tdata->file_recv_buf);
            tdata->file_recv_buf = NULL;
            tdata->file_recv_len = 0;
            return server_error(E_BADVAULT, "Invalid vault magic!");
        }

        if (hdr->version != V_VERSION) {
            free(tdata->file_recv_buf);
            tdata->file_recv_buf = NULL;
            tdata->file_recv_len = 0;
            return server_error(E_BADVAULT, "Invalid vault version!");
        }

        uint8_t *hash = sha_256_hash((uint8_t *)hdr + 10 + HASH_LEN, tdata->file_recv_len - 10 - HASH_LEN);
        if (!hash) {
            free(tdata->file_recv_buf);
            tdata->file_recv_buf = NULL;
            tdata->file_recv_len = 0;

            return server_error(E_INTERNALERR, "Failed to hash vault data!");
        }

        if (memcmp(hash, hdr->hash, HASH_LEN)) {
            free(hash);
            free(tdata->file_recv_buf);
            tdata->file_recv_buf = NULL;
            tdata->file_recv_len = 0;

            return server_error(E_BADVAULT, "Verification failed for vault: invalid hash!");
        }

        free(hash);

        char *vault_path = ec_malloc(strlen(VAULTS_DIR) + HASH_LEN * 2 + strlen(".pwmngr") + 1);
        char *email_hash = hash_email(email);
        sprintf(vault_path, "%s%s.pwmngr", VAULTS_DIR, email_hash);
        free(email_hash);
        lock_file(vault_path);
        FILE *fp = fopen(vault_path, "wb");
        if (!fp) {
            unlock_file(vault_path);
            free(vault_path);
            if (tdata->file_recv_buf) {
                free(tdata->file_recv_buf);
                tdata->file_recv_buf = NULL;
            }
            tdata->file_recv_len = 0;
            return server_error(E_INTERNALERR, "Failed to open/create user vault!");
        }

        size_t written = 0;

        while (written < tdata->file_recv_len) {
            size_t n = fwrite(tdata->file_recv_buf + written, 1, tdata->file_recv_len - written, fp);
            if (n == 0) {
                unlock_file(vault_path);
                free(vault_path);
                if (tdata->file_recv_buf) {
                    free(tdata->file_recv_buf);
                    tdata->file_recv_buf = NULL;
                }
                tdata->file_recv_len = 0;
                fclose(fp);
                L_ERROR("Failed to write data to vault file!");
                return server_error(E_INTERNALERR, "Failed to write to vault file!");
            }
            written += n;
        }

        fclose(fp);
        unlock_file(vault_path);
        free(vault_path);

        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
        cJSON_AddNumberToObject(response, "bytes_written", written);
        return response;
    }

    if (!tdata->file_recv_buf)
        tdata->file_recv_buf = ec_malloc(data_len);
    else
        tdata->file_recv_buf = ec_realloc(tdata->file_recv_buf, tdata->file_recv_len + data_len);

    memcpy(tdata->file_recv_buf, fdata, data_len);
    tdata->file_recv_len += data_len;

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", DATA_WAIT);
    return response;
}

static int handle_request(char *request, int request_len, char *response_buf, size_t response_buf_len,
                          ThreadData *tdata) {

    if (!strcmp(request, "GETSERVERINFO")) {

        char server_info[768];

#ifdef NO_DETAILED_SERVER_INFO
        strncpy(server_info, SERVER_INFO, sizeof(server_info) - 1);
#else
        struct utsname info;
        uname(&info);

        char cpu_model[256] = {0};

        lock_file("/proc/cpuinfo");
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

        unlock_file("/proc/cpuinfo");

        snprintf(server_info, sizeof(server_info), "%s\n%s %s %s\n%s", SERVER_INFO, info.sysname, info.release,
                 info.machine, cpu_model);
#endif

        cJSON *root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "code", 0);
        cJSON_AddStringToObject(root, "server_version", SERVER_VERSION);
        cJSON_AddBoolToObject(root, "smtp_enabled", smtp_enabled());
        cJSON_AddStringToObject(root, "info", server_info);

        char *response = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);

        strncpy(response_buf, response, response_buf_len - 1);
        free(response);
        return strlen(response_buf);
    }

    cJSON *response_j;

    if (!strncmp(request, "REQUEST", strlen("REQUEST"))) { // request

        cJSON *root = cJSON_Parse(request + strlen("REQUEST"));
        if (!root)
            return -1; // bad/malformed request

        cJSON *request_name = cJSON_GetObjectItem(root, "request");
        if (!request_name || !cJSON_IsString(request_name)) {
            cJSON_Delete(root);
            return -1;
        }

#define REQUEST_EQ(name) !strcmp(request_name->valuestring, name)

        if (REQUEST_EQ("CREATEACCOUNT")) {

            response_j = run_create_account(root, tdata);

            cJSON_Delete(root);
            goto send_response;
        }

        if (REQUEST_EQ("UPDATEACCOUNT")) {

            response_j = run_update_account(root, tdata);

            cJSON_Delete(root);
            goto send_response;
        }

        if (REQUEST_EQ("DELETEACCOUNT")) {

            response_j = run_delete_account(root);

            cJSON_Delete(root);
            goto send_response;
        }

        if (REQUEST_EQ("IMPORTACCOUNT")) {

            response_j = run_import_account(root);

            cJSON_Delete(root);
            goto send_response;
        }

        if (REQUEST_EQ("AUTH")) {

            response_j = run_auth(root, tdata);

            cJSON_Delete(root);
            goto send_response;
        }

        if (REQUEST_EQ("INVALIDATETOKENS")) {

            response_j = run_invalidate_tokens(root);

            cJSON_Delete(root);
            goto send_response;
        }

        if (REQUEST_EQ("GETACCOUNTINFO")) {

            response_j = run_get_account_info(root);

            cJSON_Delete(root);
            goto send_response;
        }

        if (REQUEST_EQ("GETVAULT")) {

            response_j = run_get_vault(root, tdata, send_pwmngr_file_packet);

            cJSON_Delete(root);
            goto send_response;
        }

        if (REQUEST_EQ("PUSHVAULT")) {

            response_j = run_push_vault(root, tdata);

            cJSON_Delete(root);
            goto send_response;
        }

        response_j = cJSON_CreateObject();
        cJSON_AddNumberToObject(response_j, "code", E_UNKNOWNREQ);
        cJSON_AddStringToObject(response_j, "err", "Unknown/unsupported request!");

        goto send_response;
    }

    if (!strncmp(request, "DATA", strlen("DATA"))) { // data exchange

        switch (tdata->ed) {
        case D_NONE:
            break;

        case D_CA_EMAIL_VERIFICATION_CODE:
            if (request_len < 11) {
                response_j = server_error(
                    E_INVALIDDATA,
                    "Invalid data length for verification code! (expected \"DATA\" + uint32_t + valid email)");
                goto send_response;
            }

            int32_t ca_code = *(int32_t *)(request + 4);

            char *ca_veri_email = ec_malloc(request_len - 7);
            memcpy(ca_veri_email, (char *)(request + 8), request_len - 8);
            ca_veri_email[request_len - 8] = 0;

            if (ca_code < 0 || ca_code > 999999) {
                free(ca_veri_email);
                response_j = server_error(E_INVALIDDATA, "Invalid verification code! (expected 0 <= code <= 999999)");
                goto send_response;
            }

            // NULL because new_acc is only passed when no verification is required
            response_j = finish_create_account(ca_veri_email, ca_code, NULL);
            free(ca_veri_email);

            goto send_response;

        case D_UA_EMAIL_VERIFICATION_CODE:
            if (request_len < 4 + TOKEN_LEN + (int)sizeof(uint32_t) + 3 * 2 + (int)sizeof(uint16_t) * 2) {
                response_j =
                    server_error(E_INVALIDDATA, "Invalid data length for verification code! (expected \"DATA\" + token "
                                                "+ uint32_t + uint16_t + new email + uint16_t + old email)");
                goto send_response;
            }

            int32_t ua_code = *(int32_t *)(request + 4 + TOKEN_LEN);

            uint16_t ua_veri_email_len = *(uint16_t *)(request + 4 + TOKEN_LEN + sizeof(uint32_t));
            if (request_len <
                4 + TOKEN_LEN + (int)sizeof(uint32_t) + (int)sizeof(uint16_t) * 2 + ua_veri_email_len + 3) {
                response_j = server_error(E_INVALIDDATA,
                                          "Invalid data length for verification ua_code! (expected \"DATA\" + token "
                                          "+ uint32_t + uint16_t + new email + uint16_t + old email)");
                goto send_response;
            }
            char *ua_veri_email = ec_malloc(ua_veri_email_len + 1);
            memcpy(ua_veri_email, (char *)(request + 4 + TOKEN_LEN + sizeof(uint32_t) + sizeof(uint16_t)),
                   ua_veri_email_len);
            ua_veri_email[ua_veri_email_len] = 0;

            uint16_t ua_old_email_len =
                *(uint16_t *)(request + 4 + TOKEN_LEN + sizeof(uint32_t) + sizeof(uint16_t) + ua_veri_email_len);
            if (request_len < 4 + TOKEN_LEN + (int)sizeof(uint32_t) + (int)sizeof(uint16_t) * 2 + ua_veri_email_len +
                                  ua_old_email_len) {
                free(ua_veri_email);
                response_j =
                    server_error(E_INVALIDDATA, "Invalid data length for verification code! (expected \"DATA\" + token "
                                                "+ uint32_t + uint16_t + new email + uint16_t + old email)");
                goto send_response;
            }
            char *ua_old_email = ec_malloc(ua_old_email_len + 1);
            memcpy(ua_old_email, (char *)(request + 4 + TOKEN_LEN + sizeof(uint32_t) + sizeof(uint16_t)),
                   ua_old_email_len);
            ua_old_email[ua_old_email_len] = 0;

            if (ua_code < 0 || ua_code > 999999) {
                free(ua_veri_email);
                free(ua_old_email);
                response_j = server_error(E_INVALIDDATA, "Invalid verification code! (expected 0 <= code <= 999999)");
                goto send_response;
            }

            // NULL because new_acc is only passed when no verification is required
            response_j = finish_update_account(ua_veri_email, ua_old_email, (uint8_t *)(request + 4), ua_code, NULL);
            free(ua_veri_email);
            free(ua_old_email);

            goto send_response;

        case D_CHALLENGE_RESPONSE:
            if (request_len < (int)strlen("DATA") + (int)SIGNATURE_LEN + 3) {
                response_j = server_error(
                    E_INVALIDDATA, "Invalid response to challenge! (expected \"DATA\" + 64-byte signature + email)");
                goto send_response;
            }

            char *c_res_email = ec_malloc(request_len - strlen("DATA") - SIGNATURE_LEN + 1);
            memcpy(c_res_email, (char *)(request + strlen("DATA") + SIGNATURE_LEN),
                   request_len - strlen("DATA") - SIGNATURE_LEN);
            c_res_email[request_len - strlen("DATA") - SIGNATURE_LEN] = 0;

            uint32_t uid = get_uid(c_res_email);
            if (!uid) {
                free(c_res_email);
                response_j = server_error(E_NOACCOUNT, "No account found for provided email!");
                goto send_response;
            }

            response_j = finish_auth(uid, (uint8_t *)request + 4, tdata);
            free(c_res_email);

            goto send_response;

        case D_PWMNGR_FILE_TRANSFER:

            if (request_len < (int)strlen("DATA") + TOKEN_LEN + (int)sizeof(uint16_t) + 3 + (int)sizeof(uint16_t)) {
                response_j = server_error(
                    E_INVALIDDATA,
                    "Invalid pwmngr file data! (expected \"DATA\" + token + uint16_t + email + uint16_t + fdata)");
                goto send_response;
            }

            uint16_t file_email_len = *(uint16_t *)(request + 4 + TOKEN_LEN);

            if (request_len <
                (int)strlen("DATA") + TOKEN_LEN + (int)sizeof(uint16_t) + file_email_len + (int)sizeof(uint16_t)) {
                response_j = server_error(
                    E_INVALIDDATA,
                    "Invalid pwmngr file data! (expected \"DATA\" + token + uint16_t + email + uint16_t + fdata)");
                goto send_response;
            }
            char *file_email = ec_malloc(file_email_len + 1);
            memcpy(file_email, request + 4 + TOKEN_LEN + sizeof(uint16_t), file_email_len);
            file_email[file_email_len] = 0;

            uint16_t data_len = *(uint16_t *)(request + 4 + TOKEN_LEN + sizeof(uint16_t) + file_email_len);
            if (request_len < (int)strlen("DATA") + TOKEN_LEN + (int)sizeof(uint16_t) + file_email_len +
                                  (int)sizeof(uint16_t) + data_len) {
                free(file_email);
                response_j = server_error(
                    E_INVALIDDATA,
                    "Invalid pwmngr file data! (expected \"DATA\" + token + uint16_t + email + uint16_t + fdata)");
                goto send_response;
            }

            response_j = save_pwmngr_file(
                file_email, (uint8_t *)request + 4, data_len,
                (uint8_t *)request + 4 + TOKEN_LEN + sizeof(uint16_t) + file_email_len + sizeof(uint16_t), tdata);
            free(file_email);

            goto send_response;
        }

        response_j = server_error(E_UNEXPECTEDDATA, "Received unexpected data!");
        goto send_response;
    }

    return -1;

send_response:
    char *response = cJSON_PrintUnformatted(response_j);
    cJSON_Delete(response_j);

    strncpy(response_buf, response, response_buf_len - 1);
    free(response);
    return strlen(response_buf);
}

// TODO: Possible ddos point (client can open connection and never send anything)
static void handle_client_tls(SSL *ssl, char *ip) {
    char buf[4500];
    int  n;

    // per-connection state
    ThreadData tdata = {D_NONE, {0}, ip, ssl, 0, 0};

    if (ip && ip[0] && num_outstanding_codes) {

        pthread_mutex_lock(&verification_codes_lock);

        // persistent codes over multiple connections
        for (int i = 0; i < num_outstanding_codes; i++) {
            if (!strcmp(verification_codes[i].request_ip_src, ip)) {
                tdata.ed = verification_codes[i].type;
                break;
            }
        }

        pthread_mutex_unlock(&verification_codes_lock);
    }

    for (;;) {
        n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);

            if (err == SSL_ERROR_ZERO_RETURN) {
                plog(PLOG_INFO, "Connection from %s closed: client ended session", ip);
            } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                continue;
            } else {
                openssl_log_errors();
                plog(PLOG_ERROR, "TLS read error");
            }

            break;
        }

        if (strncmp(buf, "DATA", 4)) {
            buf[n] = '\0';
            plog(PLOG_DEBUG, "%s --> %s", ip, buf);
        } else {
            int   payload_len = n - 4;
            char *hex         = ec_malloc(payload_len * 3 + 1);

            char    *out = hex;
            uint8_t *p   = (uint8_t *)buf + 4;
            uint8_t *end = (uint8_t *)buf + n;

            for (; p < end; p++) {
                out += sprintf(out, "%02x", *p);
                if (p < end - 1)
                    out += sprintf(out, " ");
            }

            *out = '\0';

            plog(PLOG_DEBUG, "%s --> DATA(%s)", ip, hex);
            free(hex);
        }

        char response[2048];
        int  rlen = handle_request(buf, n, response, sizeof(response), &tdata);

        if (rlen == -1) {
            char tmp_res[50];
            snprintf(tmp_res, sizeof(tmp_res), "{\"code\":%d,\"err\":\"Bad request\"}", E_BADREQ);
            strncpy(response, tmp_res, sizeof(response) - 1);
            rlen = strlen(response);
        }

        if (rlen <= 0) {
            plog(PLOG_ERROR, "Invalid response length %d", rlen);
            continue;
        }

        plog(PLOG_DEBUG, "%s <-- %s", ip, response);

        if (SSL_write(ssl, response, rlen) <= 0) {
            openssl_log_errors();
            L_ERROR("TLS write error");
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

static void *tls_consumer(void *arg) {
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

        struct sockaddr_in addr;
        socklen_t          addrlen = sizeof(addr);

        char ip[INET_ADDRSTRLEN] = {0}; // for logging purposes
        if (getpeername(fd, (struct sockaddr *)&addr, &addrlen) == 0) {
            inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        } else {
            L_ERROR("Failed to retrieve client ip from getpeername");
        }

        if (SSL_accept(ssl) <= 0) {
            openssl_log_errors();
            SSL_free(ssl);
            close(fd);
            continue;
        }

        handle_client_tls(ssl, ip);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }

    return NULL;
}

static int save_server_data() {
    int err = 0;
    if (save_accounts())
        err |= 1;
    clean_tokens();
    if (save_tokens())
        err |= 2;
    // not saving verification codes since they expire after an hour anyway
    return err;
}

#ifndef SAVE_INTERVAL_MINUTES
#define SAVE_INTERVAL_MINUTES 5
#endif

static void *save_thread(void *arg) {
    (void)arg;
    while (1) {
        sleep(SAVE_INTERVAL_MINUTES * 60);
        int err = save_server_data();
        if (err)
            plog(PLOG_WARN, "Failed to save data to persistent storage! (accounts save %s) (tokens save %s)",
                 (err & 1) ? "failed" : "ok", (err & 2) ? "failed" : "ok");
        else
            L_DEBUG("Successfully saved data to persistent storage");
    }
    return NULL;
}

volatile sig_atomic_t server_stop = 0;

static void on_shutdown(int sig) {
    (void)sig;
    server_stop = 1;
}

int main() {

    if (sodium_init() < 0) {
        L_FATAL("sodium_init failed!");
        return 1;
    }

    // accounts.bin

    // no locking necessary until other threads are alive
    FILE *accounts_fp = fopen(ACCOUNTS_FILE, "rb");
    if (!accounts_fp) {
        L_ERROR("Failed to open accounts file! (trying to create it)");

        int fd      = open(ACCOUNTS_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        accounts_fp = fdopen(fd, "wb");

        if (!accounts_fp) {
            L_FATAL("Failed to create accounts file!");
            return 2;
        }

        ServerAccountHeader *hdr = ec_calloc(1, sizeof(ServerAccountHeader));
        memcpy(hdr->magic, SERVER_ACCOUNT_FILE_MAGIC, strlen(SERVER_ACCOUNT_FILE_MAGIC));
        hdr->version  = SERVER_ACCOUNT_FILE_VERSION;
        uint8_t *hash = sha_256_hash((uint8_t *)hdr + 10 + HASH_LEN, sizeof(ServerAccountHeader) - 10 - HASH_LEN);
        if (!hash) {
            L_FATAL("Failed to hash new account header!");
            free(hdr);
            fclose(accounts_fp);
            return 2;
        }
        memcpy(hdr->hash, hash, HASH_LEN);
        fwrite(hdr, 1, sizeof(ServerAccountHeader), accounts_fp);
        free(hdr);
        fclose(accounts_fp);
    } else {

        fseek(accounts_fp, 0, SEEK_END);
        long fsize = ftell(accounts_fp);
        fseek(accounts_fp, 0, SEEK_SET);

        if (fsize < (int64_t)sizeof(ServerAccountHeader)) {
            L_ERROR("accounts.bin is too small to contain a valid header!");
            fclose(accounts_fp);
            return 2;
        }

        uint8_t *accounts_buf = ec_malloc(fsize);
        fread(accounts_buf, 1, fsize, accounts_fp);
        fclose(accounts_fp);

        ServerAccountHeader *hdr = (ServerAccountHeader *)accounts_buf;

        if (memcmp(hdr->magic, SERVER_ACCOUNT_FILE_MAGIC, 6)) { // invalid magic
            L_FATAL("Invalid file format! (wrong magic bytes)");
            free(accounts_buf);
            return 2;
        }
        if (hdr->version != SERVER_ACCOUNT_FILE_VERSION) {
            L_FATAL("Invalid file format! (wrong version)");
            free(accounts_buf);
            return 2;
        }

        uint8_t *hash = sha_256_hash(accounts_buf + 10 + HASH_LEN, fsize - 10 - HASH_LEN);
        if (!hash) {
            L_FATAL("Failed to hash accounts data!");
            free(accounts_buf);
            return 2;
        }

        if (memcmp(hdr->hash, hash, HASH_LEN)) {
            L_FATAL("Could not verify accounts.bin integrity; hashes do not match!");
            free(hash);
            free(accounts_buf);
            return 2;
        }

        free(hash);

        num_accounts = hdr->num_accounts;
        accounts     = ec_calloc(num_accounts, sizeof(ServerAccount));
        int i        = 0;

        for (uint8_t *p = accounts_buf + sizeof(ServerAccountHeader);
             p < accounts_buf + sizeof(ServerAccountHeader) + num_accounts * sizeof(ServerAccount);
             p += sizeof(ServerAccount))
            memcpy(&accounts[i++], p, sizeof(ServerAccount));

        uint8_t *email_start = accounts_buf + sizeof(ServerAccountHeader) + (sizeof(ServerAccount) * num_accounts);

        int bytes_read     = 0;
        int remaining_size = fsize - (sizeof(ServerAccountHeader) + (sizeof(ServerAccount) * num_accounts));

        for (int j = 0; j < num_accounts; j++) {
            if (remaining_size - bytes_read < (int64_t)sizeof(uint16_t)) {
                L_FATAL("Invalid email structure in accounts_buf! (not enough space for email_len)");
                free_accounts();
                return 2;
            }
            memcpy(&accounts->email_len, email_start + bytes_read, sizeof(uint16_t));
            bytes_read += sizeof(uint16_t);

            if (remaining_size - bytes_read < accounts[j].email_len) {
                L_FATAL("Invalid email structure in accounts_buf! (not enough space for email)");
                free_accounts();
                return 2;
            }
            accounts[j].email = ec_malloc(accounts[j].email_len + 1);
            memcpy(accounts[j].email, email_start + bytes_read, accounts[j].email_len);
            accounts[j].email[accounts[j].email_len] = 0;
            bytes_read += accounts[j].email_len;
        }

        free(accounts_buf);
    }

    // tokens.bin

    FILE *tokens_fp = fopen(TOKENS_FILE, "rb");
    if (!tokens_fp) {
        L_ERROR("Failed to open tokens file! (trying to create it)");

        int fd    = open(TOKENS_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        tokens_fp = fdopen(fd, "wb");
        if (!tokens_fp) {
            L_FATAL("Failed to create tokens file!");
            if (accounts) {
                free_accounts();
            }
            return 3;
        }

        TokenFileHeader *hdr = ec_calloc(1, sizeof(TokenFileHeader));
        memcpy(hdr->magic, TOKEN_FILE_MAGIC, strlen(TOKEN_FILE_MAGIC));
        hdr->version  = TOKEN_FILE_VERSION;
        uint8_t *hash = sha_256_hash((uint8_t *)hdr + 10 + HASH_LEN, sizeof(TokenFileHeader) - 10 - HASH_LEN);
        if (!hash) {
            L_FATAL("Failed to hash new token file header!");
            free_accounts();
            fclose(tokens_fp);
            free(hdr);
            return 3;
        }
        memcpy(hdr->hash, hash, HASH_LEN);
        fwrite(hdr, 1, sizeof(TokenFileHeader), tokens_fp);
        free(hdr);
        fclose(tokens_fp);
    } else {

        fseek(tokens_fp, 0, SEEK_END);
        long fsize = ftell(tokens_fp);
        fseek(tokens_fp, 0, SEEK_SET);

        if (fsize < (int64_t)sizeof(TokenFileHeader)) {
            L_ERROR("tokens.bin is too small to contain a valid header!");
            fclose(tokens_fp);
            free_accounts();
            return 3;
        }

        uint8_t *tokens_buf = ec_malloc(fsize);
        fread(tokens_buf, 1, fsize, tokens_fp);
        fclose(tokens_fp);

        TokenFileHeader *hdr = (TokenFileHeader *)tokens_buf;

        if (memcmp(hdr->magic, TOKEN_FILE_MAGIC, 6)) { // invalid magic
            L_FATAL("Invalid file format! (wrong magic bytes)");
            free(tokens_buf);
            free_accounts();
            return 3;
        }
        if (hdr->version != TOKEN_FILE_VERSION) {
            L_FATAL("Invalid file format! (wrong version)");
            free(tokens_buf);
            free_accounts();
            return 3;
        }

        uint8_t *hash = sha_256_hash(tokens_buf + 10 + HASH_LEN, fsize - 10 - HASH_LEN);
        if (!hash) {
            L_FATAL("Failed to hash tokens data!");
            free(tokens_buf);
            free_accounts();
            return 3;
        }

        if (memcmp(hdr->hash, hash, HASH_LEN)) {
            L_FATAL("Could not verify tokens.bin integrity; hashes do not match!");
            free(hash);
            free(tokens_buf);
            free_accounts();
            return 3;
        }

        free(hash);

        num_tokens = hdr->num_tokens;
        tokens     = ec_malloc(sizeof(ServerAccount) * num_tokens);
        int i      = 0;

        for (uint8_t *p = tokens_buf + sizeof(TokenFileHeader);
             p < tokens_buf + sizeof(TokenFileHeader) + num_tokens * sizeof(AuthToken); p += sizeof(AuthToken))
            memcpy(&tokens[i++], p, sizeof(AuthToken));

        free(tokens_buf);
    }

    if (load_smtp_config() < 0) {
        L_FATAL("Failed to load smtp.conf!");
        return 4;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        openssl_log_errors();
        free_accounts();
        if (tokens)
            free(tokens);
        return 5;
    }

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CRT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_load_verify_locations(ctx, CA_CRT, NULL) <= 0) {
        openssl_log_errors();
        free_accounts();
        if (tokens)
            free(tokens);
        return 6;
    }

    struct sigaction sa = {0};
    sa.sa_handler       = on_shutdown;
    sigaction(SIGTERM, &sa, NULL);

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_t tid;
        pthread_create(&tid, NULL, tls_consumer, NULL);
        pthread_detach(tid);
    }

    pthread_t save_tid;
    pthread_create(&save_tid, NULL, save_thread, NULL);
    pthread_detach(save_tid);

    int                server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        L_FATAL("Failed to create socket\n");
        free_accounts();
        if (tokens)
            free(tokens);
        return 7;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        L_FATAL("Failed to bind socket\n");
        free_accounts();
        if (tokens)
            free(tokens);
        return 8;
    }

    if (listen(server_fd, 10) < 0) {
        L_FATAL("listen() call failed for server_fd\n");
        free_accounts();
        if (tokens)
            free(tokens);
        return 9;
    }

    plog(PLOG_INFO, "Listening on port %d\n", PORT);

    while (!server_stop) {
        client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
        if (client_fd < 0) {
            L_ERROR("Failed to accept connection");
            continue;
        }

        plog(PLOG_INFO, "Received connection from %s", inet_ntoa(addr.sin_addr));

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

    int err = save_server_data();
    if (err)
        plog(PLOG_WARN, "Failed to save data to persistent storage! (accounts save %s) (tokens save %s)",
             (err & 1) ? "failed" : "ok", (err & 2) ? "failed" : "ok");

    close(server_fd);
    free_accounts();
    if (tokens)
        free(tokens);
    if (verification_codes)
        free(verification_codes);
    return 0;
}
