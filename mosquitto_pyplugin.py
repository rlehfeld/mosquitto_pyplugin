import cffi
import os.path
ffibuilder = cffi.FFI()

prefix = os.path.splitext(__file__)[0]
plugin = os.path.basename(prefix)
export_file = prefix + "_export.h"
impl_file = prefix + "_impl.c"

with open(impl_file) as f:
    ffibuilder.set_source(plugin, f.read())

with open(export_file) as f:
    ffibuilder.cdef(f.read())

ffibuilder.embedding_init_code(f"""
    from {plugin} import ffi

    @ffi.def_extern()
    def init_python():
        print("in init_python")
        pass
""")

ffibuilder.compile(target=f"{plugin}.*", verbose=True)
