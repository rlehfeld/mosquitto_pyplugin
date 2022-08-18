#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <Python.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <mosquitto_broker.h>

#if !defined(LIBMOSQUITTO_VERSION_NUMBER) || LIBMOSQUITTO_VERSION_NUMBER < 1005001
#error "mosquitto 1.5.1 or higher is required"
#endif

#if PY_MAJOR_VERSION >= 3
#define PY_BUILD_BYTES  "y"
#else
#define PY_BUILD_BYTES  "s"
#endif

struct pyplugin_data {
    char *module_name;
    PyObject *module;
    PyObject *plugin_cleanup_func;
    PyObject *unpwd_check_func;
    PyObject *acl_check_func;
    PyObject *security_init_func;
    PyObject *security_cleanup_func;
    PyObject *psk_key_get_func;
};

#define unused  __attribute__((unused))

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
static void debug(const char *fmt unused, ...)
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

static void Log(int loglevel, char* message)
{
    mosquitto_log_printf(loglevel, "%s", message);
}

static bool topic_matches_sub(char* sub, char* topic)
{
    bool res = false;
    mosquitto_topic_matches_sub(sub, topic, &res);
    return res;
}

/* Plugin entry points */

CFFI_DLLEXPORT int mosquitto_auth_plugin_version(void)
{
    return MOSQ_AUTH_PLUGIN_VERSION;
}

static PyObject *make_auth_opts_tuple(struct mosquitto_opt *auth_opts, int auth_opt_count)
{
    PyObject *optlist = PyTuple_New(auth_opt_count - 1); /* -1 because of skipped "pyplugin_module" */
    if (NULL == optlist)
        return NULL;

    int idx = 0;
    for (int i = 0; i < auth_opt_count; i++) {
        if (!strcmp(auth_opts[i].key, "pyplugin_module"))
            continue;

        PyObject *elt = PyTuple_Pack(2,
                                     PyUnicode_FromString(auth_opts[i].key),
                                     PyUnicode_FromString(auth_opts[i].value));
        if (NULL == elt) {
            Py_DECREF(optlist);
            return NULL;
        }

        PyTuple_SET_ITEM(optlist, idx++, elt);
    }

    return optlist;
}

CFFI_DLLEXPORT int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
    struct pyplugin_data *data = calloc(1, sizeof(*data));
    assert(NULL != data);

    for (int i = 0; i < auth_opt_count; i++) {
        if (!strcmp(auth_opts[i].key, "pyplugin_module")) {
            data->module_name = strdup(auth_opts[i].value);
            debug("pyplugin_module = %s", data->module_name);
        }
    }
    if (NULL == data->module_name)
        die(false, "pyplugin_module config param missing");

    if (!cffi_start_python())
        die(false, "failed to start python");

    data->module = PyImport_ImportModule(data->module_name);
    if (NULL == data->module)
        die(true, "failed to import module: %s", data->module_name);

    data->plugin_cleanup_func = PyObject_GetAttrString(data->module, "plugin_cleanup");
    data->unpwd_check_func = PyObject_GetAttrString(data->module, "unpwd_check");
    data->acl_check_func = PyObject_GetAttrString(data->module, "acl_check");
    data->security_init_func = PyObject_GetAttrString(data->module, "security_init");
    data->security_cleanup_func = PyObject_GetAttrString(data->module, "security_cleanup");
    data->psk_key_get_func = PyObject_GetAttrString(data->module, "psk_key_get");
    PyErr_Clear();  /* don't care about AttributeError from above code */

    PyObject *init_func = PyObject_GetAttrString(data->module, "plugin_init");
    if (NULL != init_func) {
        PyObject *optlist = make_auth_opts_tuple(auth_opts, auth_opt_count);
        if (NULL == optlist)
            die(true, "python module initialization failed");

        PyObject *res = PyObject_CallFunctionObjArgs(init_func, optlist, NULL);
        if (NULL == res)
            die(true, "python module initialization failed");
        Py_DECREF(res);

        Py_DECREF(optlist);
        Py_DECREF(init_func);
    }
    PyErr_Clear();

    *user_data = data;
    return MOSQ_ERR_SUCCESS;
}

CFFI_DLLEXPORT int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts unused, int auth_opt_count unused)
{
    struct pyplugin_data *data = user_data;

    if (NULL != data->plugin_cleanup_func) {
        PyObject *res = PyObject_CallFunction(data->plugin_cleanup_func, NULL);
        if (NULL == res) {
            fprintf(stderr, "pyplugin cleanup failed\n");
            PyErr_Print();
        }
        Py_XDECREF(res);
    }

    Py_DECREF(data->module);
    Py_XDECREF(data->plugin_cleanup_func);
    Py_XDECREF(data->unpwd_check_func);
    Py_XDECREF(data->acl_check_func);
    Py_XDECREF(data->security_init_func);
    Py_XDECREF(data->security_cleanup_func);
    Py_XDECREF(data->psk_key_get_func);
    free(data->module_name);
    free(data);
    return MOSQ_ERR_SUCCESS;
}

CFFI_DLLEXPORT int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
    struct pyplugin_data *data = user_data;

    if (NULL == data->security_init_func)
        return MOSQ_ERR_SUCCESS;

    PyObject *optlist = make_auth_opts_tuple(auth_opts, auth_opt_count);
    if (NULL == optlist)
        goto err_no_optlist;

    PyObject *py_reload = PyBool_FromLong(reload);

    PyObject *res = PyObject_CallFunctionObjArgs(data->security_init_func, optlist, py_reload, NULL);
    if (NULL == res)
        goto err_call_failed;
    Py_DECREF(res);

    Py_DECREF(py_reload);
    Py_DECREF(optlist);

    return MOSQ_ERR_SUCCESS;

err_call_failed:
    Py_XDECREF(py_reload);
    Py_XDECREF(optlist);
err_no_optlist:
    fprintf(stderr, "pyplugin security_init failed\n");
    PyErr_Print();
    return MOSQ_ERR_UNKNOWN;
}

CFFI_DLLEXPORT int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *auth_opts unused, int auth_opt_count unused, bool reload)
{
    struct pyplugin_data *data = user_data;

    if (NULL == data->security_cleanup_func)
        return MOSQ_ERR_SUCCESS;

    PyObject *py_reload = PyBool_FromLong(reload);

    PyObject *res = PyObject_CallFunctionObjArgs(data->security_cleanup_func, py_reload, NULL);
    Py_DECREF(py_reload);
    if (NULL == res) {
        fprintf(stderr, "pyplugin security_cleanup failed\n");
        PyErr_Print();
        return MOSQ_ERR_UNKNOWN;
    }
    Py_DECREF(res);

    return MOSQ_ERR_SUCCESS;
}

CFFI_DLLEXPORT int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg)
{
    struct pyplugin_data *data = user_data;

    if (NULL == data->acl_check_func)
        return MOSQ_ERR_ACL_DENIED;

    const char *client_id = mosquitto_client_id(client);
    const char *username = mosquitto_client_username(client);

    PyObject *res = PyObject_CallFunction(data->acl_check_func, "sssi" PY_BUILD_BYTES "#",
                                          client_id,
                                          username,
                                          msg->topic,
                                          access,
                                          msg->payload,
                                          msg->payloadlen);
    if (NULL == res) {
        PyErr_Print();
        return MOSQ_ERR_UNKNOWN;
    }
    int ok = PyObject_IsTrue(res);
    Py_DECREF(res);

    return ok ? MOSQ_ERR_SUCCESS : MOSQ_ERR_ACL_DENIED;
}

CFFI_DLLEXPORT int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client unused, const char *username, const char *password)
{
    struct pyplugin_data *data = user_data;

    if (NULL == username || NULL == password)
        return MOSQ_ERR_AUTH;

    debug("mosquitto_auth_unpwd_check: username=%s, password=%s", username, password);

    if (NULL == data->unpwd_check_func)
        return MOSQ_ERR_AUTH;

    PyObject *res = PyObject_CallFunction(data->unpwd_check_func, "ss", username, password);
    if (NULL == res) {
        PyErr_Print();
        return MOSQ_ERR_UNKNOWN;
    }

    int ok = PyObject_IsTrue(res);
    Py_DECREF(res);

    return ok ? MOSQ_ERR_SUCCESS : MOSQ_ERR_AUTH;
}

CFFI_DLLEXPORT int mosquitto_auth_psk_key_get(void *user_data,
					      struct mosquitto *client unused,
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
