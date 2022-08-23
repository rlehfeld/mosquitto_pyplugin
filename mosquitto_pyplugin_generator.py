import cffi
import os.path
ffibuilder = cffi.FFI()

plugin = os.path.basename(__file__).replace('_generator.py', '')
prefix = os.path.join(os.path.dirname(__file__), plugin)
export_file = prefix + "_export.h"
impl_file = prefix + "_impl.c"

with open(impl_file) as f:
    ffibuilder.set_source('_' + plugin,
                          f'#define PLUGIN_NAME "{plugin}"\n' + f.read(),
                          extra_compile_args=["-Werror", "-Wall", "-Wextra"])

with open(export_file) as f:
    ffibuilder.cdef(f.read())

ffibuilder.embedding_init_code(f"""
    from _{plugin} import ffi, lib
    from {plugin} import _newhandler, _to_string


    _HANDLER = []


    class dotdict(dict):
        '''dot.notation access to dictionary attributes'''
        __getattr__ = dict.get
        __setattr__ = dict.__setitem__
        __delattr__ = dict.__delitem__

        def copy(self):
            return dotdict(self)

    def from_payload(payload, payloadlen):
        if payload is None or payload == ffi.NULL:
            return None
        return bytes(ffi.unpack(ffi.cast('char*', payload), payloadlen))

    @ffi.def_extern()
    def _py_plugin_init(options, option_count):
        handler = _newhandler()
        plugin_options = ffi.unpack(options, option_count)
        res = handler.plugin_init({{_to_string(o.key): _to_string(o.value)
                                  for o in plugin_options}})
        if res == lib.MOSQ_ERR_SUCCESS:
            user_data = ffi.new_handle(handler)
            _HANDLER.append(user_data)
            return user_data
        return None


    @ffi.def_extern()
    def _py_plugin_cleanup(options, option_count):
        obj = ffi.from_handle(user_data)
        plugin_options = ffi.unpack(options, option_count)
        res = obj.plugin_cleanup({{_to_string(o.key): _to_string(o.value)
                                 for o in plugin_options}})
        _HANDLER.remove(user_data)


    @ffi.def_extern()
    def _py_basic_auth(user_data, client, username, password):
        obj = ffi.from_handle(user_data)
        username = _to_string(username)
        password = _to_string(password)
        return obj.basic_auth(client, username, password)


    @ffi.def_extern()
    def _py_acl_check(user_data, client, topic, access, payload, payloadlen):
        obj = ffi.from_handle(user_data)
        topic = _to_string(topic)
        payload = from_payload(payload, payloadlen)
        return obj.acl_check(client, topic, access, payload)


    @ffi.def_extern()
    def _py_psk_key(user_data, client, identity, hint,
                    key, max_key_len):
        obj = ffi.from_handle(user_data)
        identity = _to_string(identity)
        hint = _to_string(hint)
        psk = obj.psk_key(client, identity, hint)
        if psk is None:
            return lib.MOSQ_ERR_PLUGIN_DEFER
        if not psk:
            return lib.MOSQ_ERR_AUTH
        psk_encoded = ret.encode('UTF8')
        if len(key_ret) >= max_key_len:
            return lib.MOSQ_ERR_AUTH
        psk_cstr = ffi.new('char[]', psk_encoded)
        lib.strncpy(key, psk_cstr, max_key_len)
        return lib.MOSQ_ERR_SUCCESS


    @ffi.def_extern()
    def _py_disconnect(user_data, client, reason):
        obj = ffi.from_handle(user_data)
        obj.disconnect(client, reason)
        return lib.MOSQ_ERR_SUCCESS


    @ffi.def_extern()
    def _py_message(user_data, client, event_message):
        obj = ffi.from_handle(user_data)
        message = dotdict()
        message.topic = _to_string(event_message.topic)
        message.payload = from_payload(
            event_message.payload,
            event_message.payloadlen
        )
        message.qos = event_message.qos
        message.retain = event_message.retain
        orig_message = message.copy()
        res = obj.message(client, message)
        if orig_message.topic is not message.topic:
           topic_cstr = ffi.new('char[]', message.topic.encode('UTF8'))
           event_message.topic = lib._mosq_strdup(topic_cstr)
        if orig_message.payload is not message.payload:
           if isinstance(message.payload, str):
               payload = message.payload.encode('UTF8')
           else:
               payload = message.payload
           payload_vptr = ffi.new('char[]', payload)
           event_message.payload = lib._mosq_copy(payload_vptr, len(payload))
           event_message.payloadlen = len(payload)
        event_message.qos = message.qos
        event_message.retain = message.retain
        return res
""")

ffibuilder.compile(target=f"{plugin}.*", verbose=True)
