from cffi import FFI

ffi = FFI()
ffi.cdef("int read_dczid();")

code = r"""
int read_dczid() {
    int v;
    __asm__ __volatile__ (
        "mrs %0, dczid_el0" : "=r"(v)
    );
    return v;
}
"""
lib = ffi.verify(code)

def read():
    return lib.read_dczid()

