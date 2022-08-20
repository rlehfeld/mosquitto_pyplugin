from _mosquitto_pyplugin import ffi, lib
import importlib

# TODO: remove next line once implementation is done
import sys


class MosquittoCallbackHandler(object):
    def __init__(self):
        self._userdata = ffi.new_handle(self)
        self._modules = []

    @property
    def user_data(self):
        """
        User Data used in the c-part which will be
        passed to the mosquitto plugin interface
        """
        return self._userdata

    def plugin_init(self, options):
        modules = [v for k, v in options.items() if k == "pyplugin_module"]
        options = {k: v for k, v in options.items() if k != "pyplugin_module"}

        for m in modules:
            module = importlib.import_module(m)
            if hasattr(module, 'plugin_init'):
                module.plugin_init(options)
            self._modules.append(module)

    def unpwd_check(self, username, password):
        for module in self._modules:
            if hasattr(module, 'unpwd_check'):
                result = module.unpwd_check(username, password)
                if result != lib.MOSQ_ERR_PLUGIN_DEFER:
                    return result
        return lib.MOSQ_ERR_PLUGIN_DEFER


_HANDLER = MosquittoCallbackHandler()


def gethandler():
    return _HANDLER


def log(loglevel, message):
    cstr = ffi.new("char[]", message.encode('UTF8'))
    lib._mosq_log(loglevel, cstr)


def topic_matches_sub(sub, topic):
    sub_cstr = ffi.new("char[]", sub.encode('UTF8'))
    topic_cstr = ffi.new("char[]", topic.encode('UTF8'))
    return lib._mosq_topic_matches_sub(sub_cstr, topic_cstr)


def __getattr__(name):
    if name and name[0] != '_' and hasattr(lib, name):
        return getattr(lib, name)
    raise AttributeError(f"module {__name__} has no attribute {name}")
