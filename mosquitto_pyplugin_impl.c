#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <Python.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <mosquitto_broker.h>

struct pyplugin_data {
    mosquitto_plugin_id_t *identifier;
    void *user_data;
};

#define _UNUSED_ATR  __attribute__((unused))

#ifdef PYPLUGIN_DEBUG
__attribute__((format(printf, 1, 2)))
static void debug(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
#else
static void debug(const char *fmt _UNUSED_ATR, ...)
{
}
#endif

__attribute__((format(printf, 2, 3)))
static void die(bool print_exception, const char *fmt, ...)
{
    if (print_exception)
        PyErr_Print();
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void _mosq_log(int loglevel, char* message)
{
    mosquitto_log_printf(loglevel, "%s", message);
}

static const char *_mosq_client_address(const struct mosquitto *client)
{
    return mosquitto_client_address(client);
}

static const char *_mosq_client_id(const struct mosquitto *client)
{
    return mosquitto_client_id(client);
}

static int _mosq_client_protocol(const struct mosquitto *client)
{
    return mosquitto_client_protocol(client);
}

static int _mosq_client_protocol_version(const struct mosquitto *client)
{
    return mosquitto_client_protocol_version(client);
}

static const char *_mosq_client_username(const struct mosquitto *client)
{
    return mosquitto_client_username(client);
}

static int _mosq_set_username(struct mosquitto *client, const char *username)
{
    return mosquitto_set_username(client, username);
}

static int _mosq_kick_client_by_clientid(const char *client_id, bool with_will)
{
    return mosquitto_kick_client_by_clientid(client_id, with_will);
}

static int _mosq_kick_client_by_username(const char *client_username, bool with_will)
{
    return mosquitto_kick_client_by_username(client_username, with_will);
}

static bool _mosq_topic_matches_sub(char* sub, char* topic)
{
    bool res = false;
    mosquitto_topic_matches_sub(sub, topic, &res);
    return res;
}

/* event callback methods */
static int _py_basic_auth(void* user_data,
                          const struct mosquitto* client,
                          const char* username,
                          const char* password);
static int handle_basic_auth(int event, void *event_data, void *user_data)
{
    struct pyplugin_data *data = user_data;
    struct mosquitto_evt_basic_auth *basic_auth_event = event_data;

    return _py_basic_auth(data->user_data,
                          basic_auth_event->client,
                          basic_auth_event->username,
                          basic_auth_event->password);
}

static int _py_acl_check(void* user_data,
                         const struct mosquitto* client,
                         const char *topic,
                         int access,
                         const unsigned char* payload,
                         uint32_t payloadlen);
static int handle_acl_check(int event, void *event_data, void *user_data)
{
    struct pyplugin_data *data = user_data;
    struct mosquitto_evt_acl_check *acl_check_event = event_data;

    return _py_acl_check(data->user_data,
                         acl_check_event->client,
                         acl_check_event->topic,
                         acl_check_event->access,
                         acl_check_event->payload,
                         acl_check_event->payloadlen);
}

/* Plugin entry points */

CFFI_DLLEXPORT int mosquitto_plugin_version(int supported_version_count,
                                            const int *supported_versions)
{
    for (int i=0; i < supported_version_count; ++i) {
        if (supported_versions[i] == MOSQ_PLUGIN_VERSION)
            return MOSQ_PLUGIN_VERSION;
    }
    return -1;
}

static void* _py_plugin_init(struct mosquitto_opt *options, int option_count);
CFFI_DLLEXPORT int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier,
                                         void ** userdata,
                                         struct mosquitto_opt *options,
                                         int option_count)
{
    static bool started = false;
    struct pyplugin_data *data = calloc(1, sizeof(*data));
    assert(NULL != data);
    data->identifier = identifier;

    if (!started) {
        if (cffi_start_python())
            die(false, "failed to start python");
        started = true;
    }
    void *user_data = _py_plugin_init(options, option_count);
    if (NULL == user_data) {
        die(false, "could not init python plugin");
    }
    data->user_data = user_data;

    // TODO: register further callbacks

    /*
     * REMINDER: every callback added here must be unregistered in the
     *           mosquitto_plugin_cleanup below
    */
    mosquitto_callback_register(identifier,
                                MOSQ_EVT_BASIC_AUTH,
                                handle_basic_auth,
                                NULL,
                                data);
    mosquitto_callback_register(identifier,
                                MOSQ_EVT_ACL_CHECK,
                                handle_acl_check,
                                NULL,
                                data);

    *userdata = data;

    return MOSQ_ERR_SUCCESS;
}

static int _py_plugin_cleanup(void* user_data, struct mosquitto_opt *options, int option_count);
CFFI_DLLEXPORT int mosquitto_plugin_cleanup(void *user_data,
                                            struct mosquitto_opt *options,
                                            int option_count)
{
    struct pyplugin_data *data = user_data;
    mosquitto_callback_unregister(data->identifier,
                                  MOSQ_EVT_BASIC_AUTH,
                                  handle_basic_auth,
                                  NULL);
    mosquitto_callback_unregister(data->identifier,
                                  MOSQ_EVT_ACL_CHECK,
                                  handle_acl_check,
                                  NULL);
    return _py_plugin_cleanup(data->user_data, options, option_count);
}

// TODO: old interfaces, still need to be removed

#if 0
CFFI_DLLEXPORT int mosquitto_auth_psk_key_get(void *user_data,
                                              struct mosquitto *client _UNUSED_ATR,
                                              const char *hint,
                                              const char *identity,
                                              char *key,
                                              int max_key_len)
{
    struct pyplugin_data *data = user_data;
    char psk[max_key_len];

    if (NULL == identity)
        return MOSQ_ERR_AUTH;

    debug("mosquitto_auth_psk_key_get: identity=%s, hint=%s", identity, hint);

    if (NULL == data->psk_key_get_func)
        return MOSQ_ERR_AUTH;

    PyObject *res = PyObject_CallFunction(data->psk_key_get_func, "ss", identity, hint);
    if (NULL == res) {
        PyErr_Print();
        return MOSQ_ERR_UNKNOWN;
    }

    if (res == Py_None || !PyObject_IsTrue(res)) {
        goto error;
    }

    if (!PyBytes_Check(res)) {
        PyObject *res2 = PyUnicode_AsASCIIString(res);
        if (NULL == res2)
            goto error;
        Py_DECREF(res);
        res = res2;
    }

    int len = snprintf(psk, sizeof(psk), "%s", PyBytes_AsString(res));
    if (len < 0) {
        fprintf(stderr, "mosquitto_auth_psk_key_get: copy psk failed\n");
        goto error;
    }

    if (len > max_key_len) {
        fprintf(stderr, "mosquitto_auth_psk_key_get: psk length [%d] > max_key_len [%d]\n", len, max_key_len);
        goto error;
    }

    debug("mosquitto_auth_psk_key_get: psk=%s", psk);
    strncpy(key, psk, max_key_len);
    Py_DECREF(res);

    return MOSQ_ERR_SUCCESS;

error:
    Py_DECREF(res);
    return MOSQ_ERR_AUTH;
}
#endif
