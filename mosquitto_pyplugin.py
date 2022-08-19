from _mosquitto_pyplugin import ffi, lib

def log(loglevel, message):
    cstr = ffi.new("char[]", message.encode('UTF8'))
    lib._mosq_log(loglevel, cstr)

def topic_matches_sub(sub, topic):
    sub_cstr = ffi.new("char[]", sub.encode('UTF8'))
    topic_cstr = ffi.new("char[]", topic.encode('UTF8'))
    return lib._mosq_topic_matches_sub(sub_cstr, topic_cstr);

def __getattr__(name):
    if name and name[0] != '_' and hasattr(lib, name):
        return getattr(lib, name)
    raise AttributeError(f"module {__name__} has no attribute {name}")
