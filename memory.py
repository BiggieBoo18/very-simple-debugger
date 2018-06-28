from ctypes          import *
from defines         import *
from privilege       import set_debug_privilege
from page_protection import get_page_info, set_page_protection, show_protection
from process         import open_process

kernel32 = windll.kernel32

set_debug_privilege()

def read_process_memory(h_process, address, length):
    page_info = get_page_info(h_process, address)
    if not page_info:
        return False
    old_protect = set_page_protection(h_process, address, page_info.RegionSize, PAGE_EXECUTE_READWRITE)
    data     = ""
    read_buf = create_string_buffer(length)
    count    = c_ulonglong(0)
    if not kernel32.ReadProcessMemory(h_process, address, read_buf, length, byref(count)):
        return False
    else:
        data = str(read_buf.raw.decode())
        return data

def write_process_memory(h_process, address, data):
    page_info = get_page_info(h_process, address)
    if not page_info:
        return False
    old_protect = set_page_protection(h_process, address, page_info.RegionSize, PAGE_EXECUTE_READWRITE)
    if not kernel32.WriteProcessMemory(h_process, address, data, len(data), 0):
        return False
    kernel32.FlushInstructionCache(h_process, None, 0)
    return True
