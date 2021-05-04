typedef struct
{
    int type;
    int version;
    int ttl;
} ip_t;

typedef struct
{
    int type;
    int len;
    char digest[32];
} tcp_t;

typedef struct
{
    int type;
    int len;
} udp_t;


typedef enum
{
    e_ttl,
    e_version,
    e_type,

    errors_num
} errors_t;

static char error_messages[errors_num][20] = {
    "TTL time out",
    "version not match",
    "invalid type"
};