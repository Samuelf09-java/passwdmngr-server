#include "server.h"
#include "cJSON.h"
#include "vldmail.h"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
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

#define MAX(a, b) (a > b ? a : b)

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

void openssl_log_errors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        const char *msg = ERR_error_string(err, NULL);
        plog(PLOG_ERROR, "OpenSSL error: %s", msg);
    }
}

uint8_t *sha_256_hash(uint8_t *data, size_t len) {
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

#define SERVER_ACCOUNT_FILE_MAGIC "PMSACC"
#define SERVER_ACCOUNT_FILE_VERSION 1

#define TOKEN_FILE_MAGIC "PWMTOK"
#define TOKEN_FILE_VERSION 1

#define HASH_LEN 32
#define SALT_LEN 16
#define UNAME_HASH_LEN HASH_LEN
#define PASSWD_HASH_LEN HASH_LEN + SALT_LEN
#define AUTH_PK_LEN 32
#define TOKEN_LEN 32

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

} EmailVerificationCode;

SmtpConfig *smtp_config = NULL;

EmailVerificationCode *verification_codes      = NULL;
int                    num_outstanding_codes   = 0;
pthread_mutex_t        verification_codes_lock = PTHREAD_MUTEX_INITIALIZER;

ServerAccount *accounts          = NULL;
int            num_accounts      = 0;
int            accounts_modified = 0;
// UserEmail     *user_emails       = NULL;
AuthToken *tokens          = NULL;
int        num_tokens      = 0;
int        tokens_modified = 0;

pthread_mutex_t accounts_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t tokens_lock   = PTHREAD_MUTEX_INITIALIZER;

static inline int smtp_enabled() {
    return smtp_config && smtp_config->use_smtp_verification && smtp_config->smtp_host &&
           smtp_config->smtp_from; // && smtp_config->smtp_user && smtp_config->smtp_pass
}

inline int gen_verification_code() {
    return randombytes_uniform(1000000);
}

int load_smtp_config() {
    if (smtp_config) {
        L_ERROR("smtp config already loaded!");
        return -1;
    }

    FILE *fp = fopen(SMTP_CONF_FILE, "r");
    if (!fp)
        return -2;

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
    return 0;
}

void free_accounts() {
    pthread_mutex_lock(&accounts_lock);
    if (!accounts)
        return;
    for (int i = 0; i < num_accounts; i++)
        if (accounts[i].email)
            free(accounts[i].email);
    free(accounts);
    pthread_mutex_unlock(&accounts_lock);
}

int save_accounts() {

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

    pthread_mutex_unlock(&accounts_lock);

    write_len += written_email_len;

    uint8_t *hash = sha_256_hash(write_buf + 10 + HASH_LEN, write_len - 10 - HASH_LEN);
    if (hash) {
        memcpy(hdr->hash, hash, HASH_LEN);
        free(hash);
    } else
        L_WARN("Failed to hash accounts data! Writing anyway with invalid hash");

    FILE *fp = fopen(ACCOUNTS_FILE, "wb");
    if (!fp) {
        L_ERROR("Failed to open accounts file to save data!");
        free(write_buf);
        return -1;
    }

    fwrite(write_buf, 1, write_len, fp);
    plog(PLOG_DEBUG, "Wrote %d bytes to accounts.bin", write_len);
    fclose(fp);

    free(write_buf);

    accounts_modified = 0;

    return 0; // success
}

uint32_t get_next_user_id() {
    uint32_t id = 0;

    pthread_mutex_lock(&accounts_lock);
    for (int i = 0; i < num_accounts; i++)
        id = MAX(id, accounts[i].user_id);
    pthread_mutex_unlock(&accounts_lock);

    return ++id;
}

// returns pointer to the token in the tokens array; caller is responsible for locks
uint8_t *assign_token(uint32_t user_id) {

    for (int i = 0; i < num_tokens; i++)
        if (tokens[i].user_id == user_id && (time_t)tokens[i].expire_time > time(NULL))
            return tokens[i].token;

    num_tokens++;
    tokens = (num_tokens - 1) ? ec_realloc(tokens, sizeof(AuthToken) * num_tokens) : ec_malloc(sizeof(AuthToken));

    tokens[num_tokens - 1].user_id     = user_id;
    tokens[num_tokens - 1].expire_time = time(NULL) + 36 * 60 * 60; // 36 hours
    randombytes_buf(tokens[num_tokens - 1].token, TOKEN_LEN);

    tokens_modified = 1;

    return tokens[num_tokens - 1].token;
}

int check_token(uint32_t user_id, char *token_b64) {

    if (user_id <= 0)
        return -1;

    int      token_len;
    uint8_t *token = b64_decode(token_b64, &token_len);
    if (!token || token_len != TOKEN_LEN)
        return -2;

    int error = 0;

    pthread_mutex_lock(&tokens_lock);

    for (int i = 0; i < num_tokens; i++) {
        if (tokens[i].user_id == user_id && !memcmp(token, tokens[i].token, TOKEN_LEN)) {
            if ((time_t)tokens[i].expire_time > time(NULL)) {
                error = 0;
                goto found_valid_token;
            } else
                error = E_EXPIREDTOKEN; // don't break, just in case there is an unexpired token
        }
    }

    if (!error)
        error = E_INVALIDTOKEN;

found_valid_token:

    pthread_mutex_unlock(&tokens_lock);

    return error;
}

void clean_tokens() {

    pthread_mutex_lock(&tokens_lock);

    for (int i = 0; i < num_tokens; i++) {
        if ((time_t)tokens[i].expire_time < time(NULL)) {
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

int save_tokens() {

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

    pthread_mutex_unlock(&tokens_lock);

    uint8_t *hash = sha_256_hash(write_buf + 10 + HASH_LEN, write_len - 10 - HASH_LEN);
    if (hash) {
        memcpy(hdr->hash, hash, HASH_LEN);
        free(hash);
    } else
        L_WARN("Failed to hash tokens data! Writing anyway with invalid hash");

    FILE *fp = fopen(TOKENS_FILE, "wb");
    if (!fp) {
        L_ERROR("Failed to open tokens file to save data!");
        free(write_buf);
        return -1;
    }

    fwrite(write_buf, 1, write_len, fp);
    plog(PLOG_DEBUG, "Wrote %d bytes to tokens.bin", write_len);
    fclose(fp);

    free(write_buf);

    tokens_modified = 0;

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

int send_verification_email(const char *to, int code) {
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
             "This code is sent to verify that you own the email address you entered when creating your account.\r\n"
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

typedef enum ExpectedData { D_NONE, D_CREATEACC_VERIFICATION_CODE, D_PWMNGR_FILE_TRANSFER } ExpectedData;

cJSON *finish_create_account(char *email, int code, ServerAccount *new_acc);

cJSON *run_create_account(cJSON *request, ExpectedData *expected_data) {

    cJSON *email_obj          = cJSON_GetObjectItem(request, "email");
    cJSON *request_resend_obj = cJSON_GetObjectItem(request, "request_resend");
    cJSON *username_hash_obj  = cJSON_GetObjectItem(request, "username_hash");
    cJSON *password_hash_obj  = cJSON_GetObjectItem(request, "password_hash");
    cJSON *auth_pk_obj        = cJSON_GetObjectItem(request, "auth_pk");

    int email_ok  = email_obj && cJSON_IsString(email_obj);
    int resend_ok = request_resend_obj && cJSON_IsBool(request_resend_obj);
    int hashes_ok = username_hash_obj && cJSON_IsString(username_hash_obj) && password_hash_obj &&
                    cJSON_IsString(password_hash_obj) && auth_pk_obj && cJSON_IsString(auth_pk_obj);

    if (!email_ok || !(resend_ok ^ hashes_ok)) {
        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", E_BADREQ);
        cJSON_AddStringToObject(response, "err",
                                "Missing/malformed fields in request! (expected email (str) & (request_resend (bool) "
                                "^ username_hash (str), password_hash (str), and auth_pk (str))");
        return response;
    }

    char *email = cJSON_GetStringValue(email_obj);

    uint8_t *username_hash = NULL;
    uint8_t *password_hash = NULL;
    uint8_t *auth_pk       = NULL;

    if (request_resend_obj && request_resend_obj->type == cJSON_True) {
        if (!smtp_enabled()) {
            cJSON *response = cJSON_CreateObject();
            cJSON_AddNumberToObject(response, "code", E_INTERNALERR);
            cJSON_AddStringToObject(response, "err",
                                    "Failed to resend email: smtp not enabled. Contact server admins to fix");
            return response;
        }
        goto resend_email;
    }

    int uname_hash_len;
    int passwd_hash_len;
    int auth_pk_len;

    username_hash = b64_decode(cJSON_GetStringValue(username_hash_obj), &uname_hash_len);
    password_hash = b64_decode(cJSON_GetStringValue(password_hash_obj), &passwd_hash_len);
    auth_pk       = b64_decode(cJSON_GetStringValue(auth_pk_obj), &auth_pk_len);

    if (!username_hash || !password_hash || !auth_pk) {
        if (username_hash)
            free(username_hash);
        if (password_hash)
            free(password_hash);
        if (auth_pk)
            free(auth_pk);

        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", E_INTERNALERR);
        cJSON_AddStringToObject(response, "err", "Failed to decode one or more base64 strings from request!");
        return response;
    }

    if (uname_hash_len != UNAME_HASH_LEN || passwd_hash_len != PASSWD_HASH_LEN || auth_pk_len != AUTH_PK_LEN) {

        free(username_hash);
        free(password_hash);
        free(auth_pk);

        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", E_BADREQ);
        char err_msg[150];
        sprintf(err_msg,
                "Invalid length for one or more base64 fields! (expected uname_hash_len == %d, passwd_hash_len == %d, "
                "and auth_pk_len == %d)",
                UNAME_HASH_LEN, PASSWD_HASH_LEN, AUTH_PK_LEN);
        cJSON_AddStringToObject(response, "err", err_msg);
        return response;
    }

    pthread_mutex_lock(&accounts_lock);
    for (int i = 0; i < num_accounts; i++) {
        if (!strcmp(accounts[i].email, email)) {

            pthread_mutex_unlock(&accounts_lock);

            free(username_hash);
            free(password_hash);
            free(auth_pk);

            cJSON *response = cJSON_CreateObject();
            cJSON_AddNumberToObject(response, "code", E_DUPEVAL);
            cJSON_AddStringToObject(response, "err", "Provided email already exists in accounts database!");
            return response;
        }
    }

    pthread_mutex_unlock(&accounts_lock);

    wchar_t wemail[320];
    size_t  converted = mbstowcs(wemail, email, sizeof(wemail) / sizeof(wchar_t));

    if (converted == (size_t)-1 || converted >= 320) {

        free(username_hash);
        free(password_hash);
        free(auth_pk);

        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", E_INTERNALERR);
        cJSON_AddStringToObject(response, "err", "Failed to convert email to wchar to validate!");
        return response;
    }

    valid_mail_t email_vld = validate_email(wemail);
    if (!email_vld.success) {

        free(username_hash);
        free(password_hash);
        free(auth_pk);

        char lib_vld_msg[256];
        wcstombs(lib_vld_msg, email_vld.message, sizeof(lib_vld_msg));
        char msg[300];
        snprintf(msg, sizeof(msg), "Invalid email address: %s", lib_vld_msg);
        msg[strlen(msg) - 1] = 0; // remove '\n'

        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", E_INVALIDEMAIL);
        cJSON_AddStringToObject(response, "err", msg);
        return response;
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

            if (!username_hash || !password_hash || !auth_pk) { // no code to resend
                cJSON *response = cJSON_CreateObject();
                cJSON_AddNumberToObject(response, "code", E_NOCODEFOUND);
                cJSON_AddStringToObject(response, "err",
                                        "Failed to find code to resend! Please resend full CREATEACCOUNT request");
                return response;
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
            verification_codes[code_idx].new_acc->email_len = strlen(email);
            verification_codes[code_idx].new_acc->email     = strdup(email);

            free(username_hash);
            free(password_hash);
            free(auth_pk);

            code = gen_verification_code();

            verification_codes[code_idx].code        = code;
            verification_codes[code_idx].expire_time = time(NULL) + 60 * 60; // 1 hour;
        }

        if (send_verification_email(email, code) < 0) {
            if (code_idx >= 0) {
                free(verification_codes[code_idx].new_acc->email);
                free(verification_codes[code_idx].new_acc);
                if (num_outstanding_codes == 1) {
                    free(verification_codes);
                    verification_codes = NULL;
                    num_outstanding_codes--;
                } else
                    verification_codes =
                        ec_realloc(verification_codes, --num_outstanding_codes * sizeof(EmailVerificationCode));
            }

            pthread_mutex_unlock(&verification_codes_lock);

            cJSON *response = cJSON_CreateObject();
            cJSON_AddNumberToObject(response, "code", E_INTERNALERR);
            cJSON_AddStringToObject(response, "err",
                                    "Failed to send email with verification code! (invalid smtp server configuration; "
                                    "contact server admins to fix)");
            return response;
        }

        pthread_mutex_unlock(&verification_codes_lock);

        *expected_data  = D_CREATEACC_VERIFICATION_CODE;
        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", DATA_WAIT);
        return response;
    } else {

        ServerAccount *new_acc = ec_malloc(sizeof(ServerAccount));
        new_acc->user_id       = 0; // tbd
        memcpy(new_acc->uname_hash, username_hash, UNAME_HASH_LEN);
        memcpy(new_acc->passwd_hash, password_hash, PASSWD_HASH_LEN);
        memcpy(new_acc->auth_pk, auth_pk, AUTH_PK_LEN);
        new_acc->email_len = strlen(email);
        new_acc->email     = strdup(email);

        free(username_hash);
        free(password_hash);
        free(auth_pk);

        return finish_create_account(email, -1, new_acc); // -1 = no code required
    }
}

cJSON *finish_create_account(char *email, int code, ServerAccount *new_acc) {

    // new_acc only set if no code is required (-1), email is required either way
    if ((code >= 0 && new_acc) || !email) {

        if (new_acc) {
            free(new_acc->email);
            free(new_acc);
        }

        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", E_INTERNALERR);
        cJSON_AddStringToObject(response, "err",
                                "Invalid data passed to finish_create_account! (expected either code OR new_acc "
                                "struct, as well as valid email pointer)");
        return response;
    }

    if (code >= 0) { // verify code

        pthread_mutex_lock(&verification_codes_lock);

        for (int i = 0; i < num_outstanding_codes; i++) {
            if (!strcmp(email, verification_codes[i].new_acc->email)) {
                if (code != verification_codes[i].code) {
                    pthread_mutex_unlock(&verification_codes_lock);

                    cJSON *response = cJSON_CreateObject();
                    cJSON_AddNumberToObject(response, "code", E_INVALIDCODE);
                    cJSON_AddStringToObject(response, "err", "Incorrect verification code for provided email");
                    return response;
                } else if ((time_t)verification_codes[i].expire_time < time(NULL)) {
                    pthread_mutex_unlock(&verification_codes_lock);

                    cJSON *response = cJSON_CreateObject();
                    cJSON_AddNumberToObject(response, "code", E_EXPIREDCODE);
                    cJSON_AddStringToObject(response, "err",
                                            "Verification code expired; try CREATEACCOUNT <email> request_resend=true");
                    return response;
                }

                new_acc = verification_codes[i].new_acc; // now owned by this function

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

        if (!new_acc) {
            cJSON *response = cJSON_CreateObject();
            cJSON_AddNumberToObject(response, "code", E_INVALIDDATA);
            cJSON_AddStringToObject(response, "err",
                                    "Invalid email address (no associated outstanding verification code)");
            return response;
        }
    }

    new_acc->user_id = get_next_user_id();

    pthread_mutex_lock(&accounts_lock);

    num_accounts++;
    accounts = (num_accounts - 1) ? ec_realloc(accounts, sizeof(ServerAccount) * num_accounts)
                                  : ec_malloc(sizeof(ServerAccount));

    // transfers ownership of char *email to accounts array
    accounts[num_accounts - 1] = *new_acc;

    accounts_modified = 1;

    pthread_mutex_unlock(&accounts_lock);

    pthread_mutex_lock(&tokens_lock);
    uint8_t *token = assign_token(new_acc->user_id);
    pthread_mutex_unlock(&tokens_lock);

    free(new_acc);

    char *token_b64 = b64_encode(token, TOKEN_LEN);
    if (!token_b64) {
        cJSON *response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "code", E_INTERNALERR);
        cJSON_AddStringToObject(response, "err",
                                "Failed to encode token as base64! Your account has been successfully created and a "
                                "token was assigned, but it could not be returned.");
        return response;
    }

    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    cJSON_AddStringToObject(response, "token", token_b64);
    free(token_b64);
    return response;
}

cJSON *run_update_account(cJSON *request) {
    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    return response;
}

cJSON *run_auth(cJSON *request) {
    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", RESPONSE_OK);
    return response;
}

int handle_request(char *request, int request_len, char *response_buf, size_t response_buf_len,
                   ExpectedData *expected_data) {

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

#define RESPONSE_EQ(name) !strcmp(request_name->valuestring, name)

        if (RESPONSE_EQ("CREATEACCOUNT")) {

            response_j = run_create_account(root, expected_data);

            cJSON_Delete(root);
            goto send_response;
        }

        if (RESPONSE_EQ("UPDATEACCOUNT")) {

            response_j = run_update_account(root);

            cJSON_Delete(root);
            goto send_response;
        }

        response_j = cJSON_CreateObject();
        cJSON_AddNumberToObject(response_j, "code", E_UNKNOWNREQ);
        cJSON_AddStringToObject(response_j, "err", "Unknown/unsupported request!");

        goto send_response;
    }

    if (!strncmp(request, "DATA", strlen("DATA"))) { // data exchange

        switch (*expected_data) {
        case D_NONE:
            break;

        case D_CREATEACC_VERIFICATION_CODE:
            if (request_len < 11) {
                response_j = cJSON_CreateObject();
                cJSON_AddNumberToObject(response_j, "code", E_INVALIDDATA);
                cJSON_AddStringToObject(
                    response_j, "err",
                    "Invalid data length for verification code! (expected \"DATA\" + uint32_t + valid email)");
                goto send_response;
            }

            int32_t code  = *(int32_t *)(request + 4);
            char   *email = ec_malloc(request_len - 7);
            memcpy(email, (char *)(request + 8), request_len - 8);
            email[request_len - 8] = 0;

            if (code < 0 || code > 999999) {
                free(email);
                response_j = cJSON_CreateObject();
                cJSON_AddNumberToObject(response_j, "code", E_INVALIDDATA);
                cJSON_AddStringToObject(response_j, "err", "Invalid verification code! (expected 0 <= code <= 999999)");
                goto send_response;
            }

            // NULL because new_acc is only passed when no verification is required
            response_j = finish_create_account(email, code, NULL);
            free(email);

            goto send_response;

        case D_PWMNGR_FILE_TRANSFER:
            //
            // goto send_data_response;
        }

        response_j = cJSON_CreateObject();
        cJSON_AddNumberToObject(response_j, "code", 1);
        cJSON_AddStringToObject(response_j, "err", "Received unexpected data!");
        goto send_response;
    }

    return -1;

send_response:
    char *response = cJSON_PrintUnformatted(response_j);
    cJSON_Delete(response_j);

    strncpy(response_buf, response, response_buf_len);
    free(response);
    return strlen(response_buf);
}

void handle_client_tls(SSL *ssl, char *ip) {
    char buf[4200];
    int  n;

    ExpectedData expected_data = D_NONE;

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
        int  rlen = handle_request(buf, n, response, sizeof(response), &expected_data);

        if (rlen == -1) {
            char tmp_res[50];
            snprintf(tmp_res, sizeof(tmp_res), "{\"code\":%d,\"err\":\"Bad request\"}", E_BADREQ);
            strncpy(response, tmp_res, sizeof(response));
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
}

int save_server_data() {
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

void *save_thread(void *arg) {
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
}

int main() {

    if (sodium_init() < 0) {
        L_FATAL("sodium_init failed!");
        return 1;
    }

    // accounts.bin

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
                L_FATAL("Invalid email structure in accounts_buf! (not enough space for struct UserEmail)");
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

    while (1) {
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
    free(tokens);
    return 0;
}
