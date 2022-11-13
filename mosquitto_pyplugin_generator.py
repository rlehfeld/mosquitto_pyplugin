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
                          extra_compile_args=["-Werror", "-Wno-error=unused-parameter", "-Wall", "-Wextra"],
                          libraries=['mosquitto'])

with open(export_file) as f:
    ffibuilder.cdef(f.read())

ffibuilder.embedding_init_code(f"""
    from _{plugin} import ffi, lib
    from {plugin} import (
        _newhandler,
        _from_binary,
        _from_cstr,
        _to_binary,
        _to_cstr,
        _properties_to_list,
        _list_to_properties,
    )
    import asyncio


    _HANDLER = []


    class dotdict(dict):
        '''dot.notation access to dictionary attributes'''
        __getattr__ = dict.get
        __setattr__ = dict.__setitem__
        __delattr__ = dict.__delitem__

        def copy(self):
            return dotdict(self)


    @ffi.def_extern()
    def _py_plugin_init(options, option_count):
        handler = _newhandler()
        plugin_options = ffi.unpack(options, option_count)
        res = handler.plugin_init({{_from_cstr(o.key): _from_cstr(o.value)
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
        res = obj.plugin_cleanup({{_from_cstr(o.key): _from_cstr(o.value)
                                 for o in plugin_options}})
        _HANDLER.remove(user_data)


    @ffi.def_extern()
    def _py_basic_auth(user_data, client, username, password):
        obj = ffi.from_handle(user_data)
        username = _from_cstr(username)
        password = _from_cstr(password)
        return obj.basic_auth(client, username, password)


    @ffi.def_extern()
    def _py_acl_check(user_data, client, topic, access, payload, payloadlen):
        obj = ffi.from_handle(user_data)
        topic = _from_cstr(topic)
        payload = _from_binary(payload, payloadlen)
        return obj.acl_check(client, topic, access, payload)


    @ffi.def_extern()
    def _py_psk_key(user_data, client, hint, identity,
                    key, max_key_len):
        obj = ffi.from_handle(user_data)
        identity = _from_cstr(identity)
        hint = _from_cstr(hint)
        psk = obj.psk_key(client, hint, identity)
        if psk is None:
            return lib.MOSQ_ERR_PLUGIN_DEFER
        if not psk:
            return lib.MOSQ_ERR_AUTH
        if isinstance(psk, str):
           psk_bytes = psk.encode('UTF8')
        else:
           psk_bytes = bytes(psk)
        if len(psk_bytes) >= max_key_len:
            return lib.MOSQ_ERR_AUTH
        lib.strncpy(key, _to_cstr(psk_bytes), max_key_len)
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
        message.topic = _from_cstr(event_message.topic)
        message.payload = _from_binary(
            event_message.payload,
            event_message.payloadlen
        )
        message.properties = _properties_to_list(
            event_message.properties
        )
        message.qos = event_message.qos
        message.retain = event_message.retain
        orig_message = message.copy()
        orig_message.properties = message.properties.copy()
        res = obj.message(client, message)

        if orig_message.topic is not message.topic:
           event_message.topic = lib._mosq_strdup(_to_cstr(message.topic))
        if orig_message.payload is not message.payload:
           payload, payloadlen = _to_binary(message.payload)
           event_message.payload = lib._mosq_copy(
               payload,
               payloadlen,
           )
           event_message.payloadlen = payloadlen
        if orig_message.properties is not message.properties:
           event_message.properties = _list_to_properties(
               message.properties
           )

        event_message.qos = message.qos
        event_message.retain = message.retain
        return res


    @ffi.def_extern()
    def _py_tick(user_data):
        # execute python event loop once
        if 0 == _HANDLER.index(user_data):
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = new_event_loop()
                asyncio.set_event_loop(loop)
            loop.stop()
            loop.run_forever()

        obj = ffi.from_handle(user_data)
        obj.tick()


    @ffi.def_extern()
    def _py_reload(user_data):
        obj = ffi.from_handle(user_data)
        return obj.reload()
""")

ffibuilder.compile(target=f"{plugin}.*", verbose=True)
