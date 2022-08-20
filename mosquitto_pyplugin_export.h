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
const int MOSQ_ERR_PLUGIN_DEFER;
const int MOSQ_ERR_AUTH;
const int MOSQ_ERR_UNKNOWN;

const int MOSQ_LOG_INFO;
const int MOSQ_LOG_NOTICE;
const int MOSQ_LOG_WARNING;
const int MOSQ_LOG_ERR;
const int MOSQ_LOG_DEBUG;
const int MOSQ_LOG_SUBSCRIBE;
const int MOSQ_LOG_UNSUBSCRIBE;

void _mosq_log(int loglevel, char* message);
bool _mosq_topic_matches_sub(char* sub, char* topic);

extern "Python" void* _py_plugin_init(struct mosquitto_opt *options, int option_count);
extern "Python" int _py_plugin_cleanup(void *user_data, struct mosquitto_opt *options, int option_count);
extern "Python" int _py_basic_auth(void* user_data, const char *client_id, const char* username, const char* password);
extern "Python" int _py_acl_check(void* user_data, const char* client_id, const char* username, const char *topic, int access, const unsigned char* payload, uint32_t payloadlen);
