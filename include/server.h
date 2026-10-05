#ifndef _SERVER_H
#define _SERVER_H

// helpful (but optional) info for client

#ifndef PORT
// default port, can be overridden by Makefile
#define PORT 7443
#endif
#define SERVER_VERSION 1.0

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
    E_INVALIDPUSH,    // push request has timestamp older than the stored vault; call GETVAULT first
} ServerResponseCode;

#endif