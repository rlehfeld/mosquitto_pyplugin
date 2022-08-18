const int MOSQ_ACL_NONE;
const int MOSQ_ACL_SUBSCRIBE;
const int MOSQ_ACL_READ;
const int MOSQ_ACL_WRITE;

const int MOSQ_LOG_INFO;
const int MOSQ_LOG_NOTICE;
const int MOSQ_LOG_WARNING;
const int MOSQ_LOG_ERR;
const int MOSQ_LOG_DEBUG;
const int MOSQ_LOG_SUBSCRIBE;
const int MOSQ_LOG_UNSUBSCRIBE;

void Log(int loglevel, char* fmt);
bool topic_matches_sub(char* sub, char* topic);
