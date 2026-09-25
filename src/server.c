#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#define ACCOUNTS_FILE "/var/lib/passwdmngrd/accounts.bin"
#define VAULTS_DIR "/var/lib/passwdmngrd/vaults/"

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

#define L_DEBUG(msg) plog(LOG_DEBUG, msg)
#define L_INFO(msg) plog(LOG_INFO, msg)
#define L_WARN(msg) plog(LOG_WARN, msg)
#define L_ERROR(msg) plog(LOG_ERROR, msg)
#define L_FATAL(msg) plog(LOG_FATAL, msg)

int main() {
    L_INFO("Startup successful!");
    exit(0);
}