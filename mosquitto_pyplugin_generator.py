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
    from {plugin} import gethandler

    # TODO: remove next line one implementation is done
    import sys


    def _to_string(cstr):
        return ffi.string(cstr).decode('utf8')


    @ffi.def_extern()
    def _py_auth_plugin_init(plugin_opts, plugin_opt_count):
        handler = gethandler()
        plugin_options = ffi.unpack(plugin_opts, plugin_opt_count)
        handler.plugin_init({{_to_string(o.key): _to_string(o.value)
                              for o in plugin_options}})
        return handler.user_data


    @ffi.def_extern()
    def _py_unpwd_check(user_data, username, password):
        object = ffi.from_handle(user_data)
        if username is not None:
            username = _to_string(username)
            password = _to_string(password)
        return object.unpwd_check(username, password)

""")

ffibuilder.compile(target=f"{plugin}.*", verbose=True)
