from ctypes    import *
from ctypes    import wintypes
from defines   import *
from privilege import set_debug_privilege, show_privilege_information

kernel32 = windll.kernel32

set_debug_privilege()

kernel32.GetModuleHandleW.argtypes = [
    wintypes.LPCWSTR,
]
kernel32.GetModuleHandleW.restype  = wintypes.HMODULE

kernel32.GetProcAddress.argtypes = [
    wintypes.HMODULE,
    wintypes.LPCVOID,
]
kernel32.GetProcAddress.restype = DWORD64

def get_func_address(dll, func):
    h_module = kernel32.GetModuleHandleW(dll)
    if not h_module:
        return False
    # print("h_module=0x{:016X}".format(h_module))
    address  = kernel32.GetProcAddress(h_module, func)
    if not address:
        return False
    # print("address=0x{:016X}".format(address))
    return address

if __name__ == "__main__":
    address = get_func_address("msvcrt.dll", b"wprintf")
    print("address=0x{:016X}".format(address))
