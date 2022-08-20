import cffi
import os.path
ffibuilder = cffi.FFI()

plugin = os.path.basename(__file__).replace('_generator.py', '')
prefix = os.path.join(os.path.dirname(__file__), plugin)
export_file = prefix + "_export.h"
impl_file = prefix + "_impl.c"

with open(impl_file) as f:
    ffibuilder.set_source('_' + plugin,
                          f'#define PLUGIN_NAME "{plugin}"\n' + f.read())

with open(export_file) as f:
    ffibuilder.cdef(f.read())

ffibuilder.embedding_init_code(f"""
    from _{plugin} import ffi, lib
    from {plugin} import newhandler

    # TODO: remove next line one implementation is done
    import sys

    _HANDLER = []

    def _to_string(cstr):
        if cstr == None or cstr == ffi.NULL:
            return None
        else:
            return ffi.string(cstr).decode('utf8')


    @ffi.def_extern()
    def _py_plugin_init(options, option_count):
        handler = newhandler()
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
    def _py_basic_auth(user_data, client_id, username, password):
        obj = ffi.from_handle(user_data)
        client_id = _to_string(client_id)
        username = _to_string(username)
        password = _to_string(password)
        return obj.basic_auth(client_id, username, password)


    @ffi.def_extern()
    def _py_acl_check(user_data, client_id, username,
                      topic, access, payload, payloadlen):
        obj = ffi.from_handle(user_data)
        client_id = _to_string(client_id)
        username = _to_string(username)
        topic = _to_string(topic)
        if payload is None or payload == ffi.NULL:
            payload = None
        else:
            payload = bytes(ffi.unpack(payload, payloadlen))
        return obj.acl_check(client_id, username, topic, access, payload)
""")

ffibuilder.compile(target=f"{plugin}.*", verbose=True)
