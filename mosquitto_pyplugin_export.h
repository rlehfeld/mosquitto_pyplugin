struct mosquitto;

struct mosquitto_opt {
    char *key;
    char *value;
};

typedef ... mosquitto_property;

struct mosquitto_evt_message {
    char *topic;
    void *payload;
    uint32_t payloadlen;
    mosquitto_property *properties;
    uint8_t qos;
    bool retain;
    ...;
};

struct mosquitto_evt_extended_auth {
    const void *const data_in;
    void *data_out;
    const uint16_t data_in_len;
    uint16_t data_out_len;
    const char *const auth_method;
    ...;
};

const int MOSQ_ACL_NONE;
const int MOSQ_ACL_READ;
const int MOSQ_ACL_WRITE;
const int MOSQ_ACL_SUBSCRIBE;
const int MOSQ_ACL_UNSUBSCRIBE;

const int MOSQ_ERR_AUTH_CONTINUE;
const int MOSQ_ERR_NO_SUBSCRIBERS;
const int MOSQ_ERR_SUB_EXISTS;
const int MOSQ_ERR_CONN_PENDING;
const int MOSQ_ERR_SUCCESS;
const int MOSQ_ERR_NOMEM;
const int MOSQ_ERR_PROTOCOL;
const int MOSQ_ERR_INVAL;
const int MOSQ_ERR_NO_CONN;
const int MOSQ_ERR_CONN_REFUSED;
const int MOSQ_ERR_NOT_FOUND;
const int MOSQ_ERR_CONN_LOST;
const int MOSQ_ERR_TLS;
const int MOSQ_ERR_PAYLOAD_SIZE;
const int MOSQ_ERR_NOT_SUPPORTED;
const int MOSQ_ERR_AUTH;
const int MOSQ_ERR_ACL_DENIED;
const int MOSQ_ERR_UNKNOWN;
const int MOSQ_ERR_ERRNO;
const int MOSQ_ERR_EAI;
const int MOSQ_ERR_PROXY;
const int MOSQ_ERR_PLUGIN_DEFER;
const int MOSQ_ERR_MALFORMED_UTF8;
const int MOSQ_ERR_KEEPALIVE;
const int MOSQ_ERR_LOOKUP;
const int MOSQ_ERR_MALFORMED_PACKET;
const int MOSQ_ERR_DUPLICATE_PROPERTY;
const int MOSQ_ERR_TLS_HANDSHAKE;
const int MOSQ_ERR_QOS_NOT_SUPPORTED;
const int MOSQ_ERR_OVERSIZE_PACKET;
const int MOSQ_ERR_OCSP;
const int MOSQ_ERR_TIMEOUT;
const int MOSQ_ERR_RETAIN_NOT_SUPPORTED;
const int MOSQ_ERR_TOPIC_ALIAS_INVALID;
const int MOSQ_ERR_ADMINISTRATIVE_ACTION;
const int MOSQ_ERR_ALREADY_EXISTS;

const int MOSQ_LOG_NONE;
const int MOSQ_LOG_INFO;
const int MOSQ_LOG_NOTICE;
const int MOSQ_LOG_WARNING;
const int MOSQ_LOG_ERR;
const int MOSQ_LOG_DEBUG;
const int MOSQ_LOG_SUBSCRIBE;
const int MOSQ_LOG_UNSUBSCRIBE;
const int MOSQ_LOG_WEBSOCKETS;
const int MOSQ_LOG_INTERNAL;
const int MOSQ_LOG_ALL;

const int MQTT_PROP_TYPE_BYTE;
const int MQTT_PROP_TYPE_INT16;
const int MQTT_PROP_TYPE_INT32;
const int MQTT_PROP_TYPE_VARINT;
const int MQTT_PROP_TYPE_BINARY;
const int MQTT_PROP_TYPE_STRING;
const int MQTT_PROP_TYPE_STRING_PAIR;

void _mosq_log(int loglevel, char* message);
const char *_mosq_strerror(int mosq_errno);
const char *_mosq_client_address(const struct mosquitto *client);
const char *_mosq_client_id(const struct mosquitto *client);
char* _mosq_client_certificate(const struct mosquitto *client);
int _mosq_client_protocol(const struct mosquitto *client);
int _mosq_client_protocol_version(const struct mosquitto *client);
const char *_mosq_client_username(const struct mosquitto *client);
int _mosq_set_username(struct mosquitto *client, const char *username);
int _mosq_kick_client_by_clientid(const char *client_id, bool with_will);
int _mosq_kick_client_by_username(const char *client_username, bool with_will);
bool _mosq_topic_matches_sub(char* sub, char* topic);

char *strncpy(char *dest, const char *src, size_t n);
void free(void *ptr);
char *_mosq_strdup(const char* s);
void *_mosq_memdup(void* src, size_t size);
void *_mosq_copy(void* src, size_t size);

extern "Python" void* _py_plugin_init(struct mosquitto_opt *options,
                                      int option_count);
extern "Python" int _py_plugin_cleanup(void *user_data,
                                       struct mosquitto_opt *options,
                                       int option_count);
extern "Python" int _py_basic_auth(void* user_data,
                                   struct mosquitto *client,
                                   const char* username,
                                   const char* password);
extern "Python" int _py_extended_auth_start(void* user_data,
                                            struct mosquitto* client,
                                            struct mosquitto_evt_extended_auth* event_extended_auth);
extern "Python" int _py_extended_auth_continue(void* user_data,
                                               struct mosquitto* client,
                                               struct mosquitto_evt_extended_auth* event_extended_auth);
extern "Python" int _py_acl_check(void* user_data,
                                  struct mosquitto* client,
                                  const char *topic,
                                  int access,
                                  const void* payload,
                                  uint32_t payloadlen);
extern "Python" int _py_psk_key(void* user_data,
                                struct mosquitto* client,
                                const char *identity,
                                const char *hint,
                                char *key,
                                int max_key_len);
extern "Python" int _py_disconnect(void* user_data,
                                   struct mosquitto* client,
                                   int reason);
extern "Python" int _py_message(void* user_data,
                                struct mosquitto* client,
                                struct mosquitto_evt_message* event_message);
extern "Python" void _py_tick(void* user_data);
extern "Python" int _py_reload(void* user_data);

int mosquitto_property_add_byte(
                        mosquitto_property **proplist,
                        int identifier,
                        uint8_t value);
int mosquitto_property_add_int16(
                        mosquitto_property **proplist,
                        int identifier,
                        uint16_t value);
int mosquitto_property_add_int32(
                        mosquitto_property **proplist,
                        int identifier,
                        uint32_t value);
int mosquitto_property_add_varint(
                        mosquitto_property **proplist,
                        int identifier,
                        uint32_t value);
int mosquitto_property_add_binary(
                        mosquitto_property **proplist,
                        int identifier,
                        const void *value,
                        uint16_t len);
int mosquitto_property_add_string(
                        mosquitto_property **proplist,
                        int identifier,
                        const char *value);
int mosquitto_property_add_string_pair(
                        mosquitto_property **proplist,
                        int identifier,
                        const char *name,
                        const char *value);
int mosquitto_property_identifier(
                        const mosquitto_property *property);
const mosquitto_property *mosquitto_property_next(
                        const mosquitto_property *proplist);
const mosquitto_property *mosquitto_property_read_byte(
                        const mosquitto_property *proplist,
                        int identifier,
                        uint8_t *value,
                        bool skip_first);
const mosquitto_property *mosquitto_property_read_int16(
                        const mosquitto_property *proplist,
                        int identifier,
                        uint16_t *value,
                        bool skip_first);
const mosquitto_property *mosquitto_property_read_int32(
                        const mosquitto_property *proplist,
                        int identifier,
                        uint32_t *value,
                        bool skip_first);
const mosquitto_property *mosquitto_property_read_varint(
                        const mosquitto_property *proplist,
                        int identifier,
                        uint32_t *value,
                        bool skip_first);
const mosquitto_property *mosquitto_property_read_binary(
                        const mosquitto_property *proplist,
                        int identifier,
                        void **value,
                        uint16_t *len,
                        bool skip_first);
const mosquitto_property *mosquitto_property_read_string(
                        const mosquitto_property *proplist,
                        int identifier,
                        char **value,
                        bool skip_first);
const mosquitto_property *mosquitto_property_read_string_pair(
                        const mosquitto_property *proplist,
                        int identifier,
                        char **name,
                        char **value,
                        bool skip_first);
const char *mosquitto_property_identifier_to_string(int identifier);
int mosquitto_string_to_property_info(
                        const char *propname,
                        int *identifier,
                        int *type);
int mosquitto_broker_publish_copy(
                        const char *clientid,
                        const char *topic,
                        int payloadlen,
                        const void *payload,
                        int qos,
                        bool retain,
                        mosquitto_property *properties);
