from _mosquitto_pyplugin import ffi, lib
import importlib

# TODO: remove next line once implementation is done
import sys


_HANDLER = []


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

    def basic_auth(self, client_id, username, password,
                   client_address, client_protocol,
                   client_protocol_version):
        for module in self._modules:
            if hasattr(module, 'basic_auth'):
                result = module.basic_auth(client_id, username, password,
                                           client_address, client_protocol,
                                           client_protocol_version)
                if result != lib.MOSQ_ERR_PLUGIN_DEFER:
                    return result

        return lib.MOSQ_ERR_PLUGIN_DEFER

    def acl_check(self, client_id, client_username,
                  client_address, client_protocol,
		  client_protocol_version, topic, access, payload):
        for module in self._modules:
            if hasattr(module, 'acl_check'):
                result = module.acl_check(
                    client_id, client_username, client_address,
                    client_protocol, client_protocol_version,
                    topic, access, payload,
                )
                if result != lib.MOSQ_ERR_PLUGIN_DEFER:
                    return result

        return lib.MOSQ_ERR_PLUGIN_DEFER


def newhandler():
    handler = MosquittoCallbackHandler()
    _HANDLER.append(handler)
    return handler


def log(loglevel, message):
    message_cstr = ffi.new("char[]", message.encode('UTF8'))
    lib._mosq_log(loglevel, message_cstr)


def kick_client_by_clientid(client_id, with_will):
    client_id_cstr = ffi.new("char[]", client_id.encode('UTF8'))
    return _mosq_kick_client_by_clientid(client_id_cstr, with_will)


def kick_client_by_username(client_username, with_will):
    client_username_cstr = ffi.new("char[]", client_username.encode('UTF8'))
    return _mosq_kick_client_by_username(client_username_cstr, with_will)


def topic_matches_sub(sub, topic):
    sub_cstr = ffi.new("char[]", sub.encode('UTF8'))
    topic_cstr = ffi.new("char[]", topic.encode('UTF8'))
    return lib._mosq_topic_matches_sub(sub_cstr, topic_cstr)


def __getattr__(name):
    if name and name[0] != '_' and hasattr(lib, name):
        return getattr(lib, name)
    raise AttributeError(f"module {__name__} has no attribute {name}")
