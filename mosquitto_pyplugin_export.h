struct mosquitto;

struct mosquitto_opt {
        char *key;
        char *value;
};

struct mosquitto_auth_opt {
        char *key;
        char *value;
};

const int MOSQ_ACL_NONE;
const int MOSQ_ACL_SUBSCRIBE;
const int MOSQ_ACL_READ;
const int MOSQ_ACL_WRITE;

const int MOSQ_ERR_SUCCESS;
const int MOSQ_ERR_INVAL;
const int MOSQ_ERR_NOMEM;
const int MOSQ_ERR_AUTH;
const int MOSQ_ERR_UNKNOWN;
const int MOSQ_ERR_PLUGIN_DEFER;

const int MOSQ_LOG_INFO;
const int MOSQ_LOG_NOTICE;
const int MOSQ_LOG_WARNING;
const int MOSQ_LOG_ERR;
const int MOSQ_LOG_DEBUG;
const int MOSQ_LOG_SUBSCRIBE;
const int MOSQ_LOG_UNSUBSCRIBE;

void _mosq_log(int loglevel, char* message);
const char *_mosq_client_address(const struct mosquitto *client);
const char *_mosq_client_id(const struct mosquitto *client);
int _mosq_client_protocol(const struct mosquitto *client);
int _mosq_client_protocol_version(const struct mosquitto *client);
const char *_mosq_client_username(const struct mosquitto *client);
int _mosq_set_username(struct mosquitto *client, const char *username);
int _mosq_kick_client_by_clientid(const char *client_id, bool with_will);
int _mosq_kick_client_by_username(const char *client_username, bool with_will);
bool _mosq_topic_matches_sub(char* sub, char* topic);
char *strncpy(char *dest, const char *src, size_t n);

extern "Python" void* _py_plugin_init(struct mosquitto_opt *options,
                                      int option_count);
extern "Python" int _py_plugin_cleanup(void *user_data,
                                       struct mosquitto_opt *options,
                                       int option_count);
extern "Python" int _py_basic_auth(void* user_data,
                                   const struct mosquitto *client,
                                   const char* username,
                                   const char* password);
extern "Python" int _py_acl_check(void* user_data,
                                  const struct mosquitto* client,
                                  const char *topic,
                                  int access,
                                  const unsigned char* payload,
                                  uint32_t payloadlen);
extern "Python" int _py_psk_key(void* user_data,
                                const struct mosquitto* client,
                                const char *identity,
                                const char *hint,
                                char *key,
                                int max_key_len);
