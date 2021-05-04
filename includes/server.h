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
    char digest[33];
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
    e_protocol_type,
    e_app_type,
    e_hash,

    errors_num
} errors_t;

static char error_messages[errors_num][30] = {
    "TTL time out",
    "version not match",
    "invalid protocol type",
    "upper layer type is invalid",
    "MD5 is diffarent"
};