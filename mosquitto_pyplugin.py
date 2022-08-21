from _mosquitto_pyplugin import ffi, lib
import importlib


_HANDLER = []


def _to_string(cstr):
    if cstr is None or cstr == ffi.NULL:
        return None
    else:
        return ffi.string(cstr).decode('utf8')


class MosquittoCallbackHandler(object):
    def __init__(self):
        self._modules = []

    def plugin_init(self, options):
        modules = [v for k, v in options.items() if k == "pyplugin_module"]
        options = {k: v for k, v in options.items() if k != "pyplugin_module"}

        for m in modules:
            module = importlib.import_module(m)
            if hasattr(module, 'plugin_init'):
                result = module.plugin_init(options)
                if result:
                    module = result
            self._modules.append(module)

        return lib.MOSQ_ERR_SUCCESS

    def plugin_cleanup(self, options):
        options = {k: v for k, v in options.items() if k != "pyplugin_module"}

        for module in self._modules:
            if hasattr(module, 'plugin_cleanup'):
                module.plugin_cleanup(options)

        _HANDLER.remove(self)

    def basic_auth(self, client, username, password):
        for module in self._modules:
            if hasattr(module, 'basic_auth'):
                result = module.basic_auth(client, username, password)
                if result != lib.MOSQ_ERR_PLUGIN_DEFER:
                    return result

        return lib.MOSQ_ERR_PLUGIN_DEFER

    def acl_check(self, client, topic, access, payload):
        for module in self._modules:
            if hasattr(module, 'acl_check'):
                result = module.acl_check(
                    client, topic, access, payload,
                )
                if result != lib.MOSQ_ERR_PLUGIN_DEFER:
                    return result

        return lib.MOSQ_ERR_PLUGIN_DEFER


    def psk_key(self, client, identity, hint):
        for module in self._modules:
            if hasattr(module, 'psk_key'):
                psk = module.psk_key(
                    client, identity, hint
                )
                if psk is not None:
                    return psk

        return None


def _newhandler():
    handler = MosquittoCallbackHandler()
    _HANDLER.append(handler)
    return handler


def log(loglevel, message):
    message_cstr = ffi.new("char[]", message.encode('UTF8'))
    lib._mosq_log(loglevel, message_cstr)


def client_address(client):
    return _to_string(lib._mosq_client_address(client))


def client_id(client):
    return _to_string(lib._mosq_client_id(client))


def client_protocol(client):
    return lib._mosq_client_protocol(client)


def client_protocol_version(client):
    return lib._mosq_client_protocol_version(client)


def client_username(client):
    return _to_string(lib._mosq_client_username(client))


def set_username(client, username):
    username_cstr = ffi.new("char[]", username.encode('UTF8'))
    return lib._mosq_set_username(client, username_cstr)


def kick_client_by_clientid(client_id, with_will):
    client_id_cstr = ffi.new("char[]", client_id.encode('UTF8'))
    return lib._mosq_kick_client_by_clientid(client_id_cstr, with_will)


def kick_client_by_username(client_username, with_will):
    client_username_cstr = ffi.new("char[]", client_username.encode('UTF8'))
    return lib._mosq_kick_client_by_username(client_username_cstr, with_will)


def topic_matches_sub(sub, topic):
    sub_cstr = ffi.new("char[]", sub.encode('UTF8'))
    topic_cstr = ffi.new("char[]", topic.encode('UTF8'))
    return lib._mosq_topic_matches_sub(sub_cstr, topic_cstr)


def __getattr__(name):
    if name and name[0] != '_' and hasattr(lib, name):
        return getattr(lib, name)
    raise AttributeError(f"module {__name__} has no attribute {name}")
