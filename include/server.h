#ifndef _SERVER_H
#define _SERVER_H

#include <sodium.h>
#include <stdint.h>

// helpful info for client

#ifndef PORT
// default port, can be overridden by Makefile
#define PORT 7443
#endif
#define SERVER_VERSION "1.0"

// max bytes to send in a packet
#define VAULT_CHUNK_SIZE 4096

// expected vault header info
#define V_MAGIC "PWMNGR"
#define V_VERSION 2

#define HASH_LEN crypto_hash_sha256_BYTES
#define AES_KEY_LEN crypto_aead_aes256gcm_KEYBYTES
#define NONCE_LEN crypto_aead_aes256gcm_NPUBBYTES
#define TAG_LEN crypto_aead_aes256gcm_ABYTES
#define SALT_LEN crypto_pwhash_SALTBYTES
#define UNAME_HASH_LEN HASH_LEN
#define PASSWD_HASH_LEN HASH_LEN + SALT_LEN
#define AUTH_PK_LEN crypto_sign_PUBLICKEYBYTES
#define AUTH_SK_LEN crypto_sign_SECRETKEYBYTES
#define TOKEN_LEN HASH_LEN
#define CHALLENGE_LEN HASH_LEN
#define SIGNATURE_LEN crypto_sign_BYTES
#define RK_LEN AES_KEY_LEN

// copied from client-side; only magic, version, hash, and timestamp are really used
typedef struct __attribute__((packed)) VaultHeader {
    char     magic[6];
    uint32_t version;
    uint8_t  hash[HASH_LEN];
    uint64_t timestamp;
    uint32_t num_entries;
    uint32_t ciphertext_len;
    uint8_t  salt[SALT_LEN]; // stored here as well as in Account struct to support exports/imports
    uint8_t  nonce[NONCE_LEN];
    uint8_t  tag[TAG_LEN];
} VaultHeader;

static uint64_t hex_to_u64(const char *hex) {
    uint64_t value = 0;

    for (int i = 0; i < 16; i++) {
        char    c = hex[i];
        uint8_t nibble;

        if (c >= '0' && c <= '9')
            nibble = c - '0';
        else if (c >= 'a' && c <= 'f')
            nibble = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            nibble = c - 'A' + 10;
        else
            return 0; // invalid char

        value = (value << 4) | nibble;
    }

    return value;
}

static void u64_to_hex(uint64_t value, char *out, int out_len) {

    if (!out || out_len < 17)
        return;

    static const char *digits = "0123456789abcdef";

    for (int i = 0; i < 16; i++) {
        uint8_t nibble = (value >> (60 - 4 * i)) & 0xF;
        out[i]         = digits[nibble];
    }

    out[16] = '\0';
}

enum ServerResponseCode {
    RESPONSE_OK,      // ok
    DATA_WAIT,        // waiting for client to send data
    E_INTERNALERR,    // internal error
    E_BADREQ,         // bad request (invalid fields)
    E_UNKNOWNREQ,     // unknown request
    E_UNEXPECTEDDATA, // received data when expected data was D_NONE
    E_DUPEVAL,        // duplicate value (like email already registered)
    E_DUPEREQ,        // duplicate request (like CREATEACCOUNT with outstanding code)
    E_INVALIDEMAIL,   // invalid email address structure (from libvldmail)
    E_INVALIDDATA,    // invalid DATA packet (not in expected format)
    E_NOCODEFOUND,    // no outstanding verification code for account creation
    E_INVALIDCODE,    // invalid verification code
    E_EXPIREDCODE,    // expired verification code
    E_BADTOKEN,       // invalid authentication token (wrong format/length; couldn't decode)
    E_INVALIDTOKEN,   // invalid authentication token (incorrect/not found for provided user id)
    E_EXPIREDTOKEN,   // expired authentication token
    E_NOACCOUNT,      // no account found for provided email
    E_BADSIGNATURE,   // invalid signature on sent challenge
    E_BADVAULT,       // invalid vault (bad size/magic/version/hash)
    E_VAULTUPTODATE,  // not completing get request (client has up-to-date vault already)
    E_CLIENTUPTODATE, // client already has up-to-date account info
    E_INVALIDPUSH,    // push request has timestamp older than the stored vault; call GETVAULT first
} ServerResponseCode;

#endif // _SERVER_H