import os
from ctypes    import *
from ctypes    import wintypes
from defines   import *
from privilege import set_debug_privilege

psapi    = windll.psapi
kernel32 = windll.kernel32

set_debug_privilege()

kernel32.OpenProcessToken.argtypes = (
    wintypes.HANDLE,
    DWORD64,
    POINTER(wintypes.HANDLE)
)
kernel32.OpenProcessToken.restype  = wintypes.BOOL

def open_process(pid):
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        return False
    return h_process

def attach(pid):
    if not kernel32.DebugActiveProcess(int(pid)):
        return False
    return True

def dettach(pid):
    if not kernel32.DebugActiveProcessStop(int(pid)):
        return False
    return True

def enum_pids():
    pids          = (DWORD*1024)()
    size          = sizeof(pids)
    return_length = DWORD(1024)
    if not psapi.EnumProcesses(byref(pids), size, byref(return_length)):
        return False
    else:
        # get again with correct size
        c = int(return_length.value/sizeof(DWORD))
        pids          = (DWORD*c)()
        size          = sizeof(pids)
        return_length = DWORD(1024)
        if not psapi.EnumProcesses(byref(pids), size, byref(return_length)):
            return False
        return pids

def process_file_name(pid):
    ret = False
    h_process = open_process(pid)
    if h_process:
        size = 256
        image_file_name = (WCHAR*size)()
        if psapi.GetProcessImageFileNameW(h_process, byref(image_file_name), size):
            ret = os.path.basename(image_file_name.value)
        kernel32.CloseHandle(h_process)
    return ret

def enum_processes():
    processes_info = []
    pids = enum_pids()
    for i, pid in enumerate(pids):
        fname = process_file_name(pid)
        if fname:
            processes_info.append((pid, fname))
    return processes_info

if __name__ == "__main__":
    pids = enum_processes()
    for i, (pid, fname) in enumerate(pids):
        print(i, pid, fname)
