from ctypes    import *
from ctypes    import wintypes
from defines   import *
from thread    import open_thread, get_thread_context, set_thread_context
from memory    import read_process_memory, write_process_memory
from privilege import set_debug_privilege

kernel32 = windll.kernel32

set_debug_privilege()

def eventname(event_code):
    name = "UNKNOWN_EVENT"
    if event_code==1:
        name = "EXCEPTION_DEBUG_EVENT"
    elif event_code==2:
        name = "CREATE_THREAD_DEBUG_EVENT"
    elif event_code==3:
        name = "CREATE_PROCESS_DEBUG_EVENT"
    elif event_code==4:
        name = "EXIT_THREAD_DEBUG_EVENT"
    elif event_code==5:
        name = "EXIT_PROCESS_DEBUG_EVENT"
    elif event_code==6:
        name = "LOAD_DLL_DEBUG_EVENT"
    elif event_code==7:
        name = "UNLOAD_DLL_DEBUG_EVENT"
    elif event_code==8:
        name = "OUTPUT_DEBUG_STRING_EVENT"
    elif event_code==9:
        name = "RIP_EVENT"
    return name

def exception_name(exception_code):
    name = "UNKNOWN_EXCEPTION"
    if exception_code==EXCEPTION_ACCESS_VIOLATION:
        name = "EXCEPTION_ACCESS_VIOLATION"
    elif exception_code==EXCEPTION_GUARD_PAGE_VIOLATION:
        name = "EXCEPTION_GUARD_PAGE_VIOLATION"
    elif exception_code==EXCEPTION_BREAKPOINT:
        name = "EXCEPTION_BREAKPOINT"
    elif exception_code==EXCEPTION_SINGLE_STEP:
        name = "EXCEPTION_SINGLE_STEP"
    elif exception_code==EXCEPTION_STACK_OVERFLOW:
        name = "EXCEPTION_STACK_OVERFLOW"
    return name

def sw_bp_handler(exception_record):
    print("Not Implemented yet")

def sw_bp_after(h_process, tid, sw_bps, exception_address):
    break_info = [info for info in sw_bps.values() if int(info[0], 16)==exception_address] # address and original_byte at break point
    if not break_info:
        return False
    break_info = break_info[0]
    h_thread = open_thread(tid)
    if not h_thread:
        return False
    context = get_thread_context(h_thread)
    if not context:
        return False
    if not write_process_memory(h_process, cast(int(break_info[0], 16), POINTER(BYTE)), break_info[1]):
        return False
    context.Rip    -= 0x1
    context.EFlags |= 1<<8
    if not set_thread_context(h_thread, context):
        return False
    context = get_thread_context(h_thread)
    if not context:
        return False
    return break_info[0]

def sw_bp_reset(h_process, tid, sw_bp_address):
    h_thread = open_thread(tid)
    if not h_thread:
        return False
    context = get_thread_context(h_thread)
    if not context:
        return False
    if not write_process_memory(h_process, cast(int(sw_bp_address, 16), POINTER(BYTE)), "\xCC"):
        return False
    context.EFlags &= ~1<<8
    if not set_thread_context(h_thread, context):
        return False
    return True

def detector(h_process, sw_bps={}):
    first_break = False # windows break
    debug_event = DEBUG_EVENT()
    print("Please to quit the detector press Ctrl-C")
    while True:
        continue_flag    = DBG_EXCEPTION_NOT_HANDLED
        try:
            if kernel32.WaitForDebugEvent(byref(debug_event), 1):
                # print("  tid:", debug_event.dwThreadId)
                # print("  DebugEventCode:", debug_event.dwDebugEventCode)
                # print("  DebugEventName:", eventname(debug_event.dwDebugEventCode))
                if eventname(debug_event.dwDebugEventCode)=="EXCEPTION_DEBUG_EVENT":
                    exception_record = debug_event.u.Exception.ExceptionRecord
                    # print("    ExceptionCode:", exception_record.ExceptionCode)
                    # print("    ExceptionName:", exception_name(exception_record.ExceptionCode))
                    # print("    ExceptionAddress: 0x{:016X}".format(exception_record.ExceptionAddress))
                    if exception_name(exception_record.ExceptionCode)=="EXCEPTION_BREAKPOINT": # software breakpoint
                        if first_break:
                            sw_bp_handler(exception_record)
                            sw_bp_address = sw_bp_after(h_process, debug_event.dwThreadId, sw_bps, exception_record.ExceptionAddress)
                            if not sw_bp_address:
                                print(WinError(GetLastError()))
                                return False
                            continue_flag = DBG_CONTINUE
                        else:
                            first_break   = True # enable first windows break
                            continue_flag = DBG_CONTINUE
                    if exception_name(exception_record.ExceptionCode)=="EXCEPTION_SINGLE_STEP": # single step
                        if sw_bp_address:
                            sw_bp_reset(h_process, debug_event.dwThreadId, sw_bp_address)
                        continue_flag = DBG_CONTINUE
                    # if exception_name(exception_record.ExceptionCode)=="EXCEPTION_ACCESS_VIOLATION": # memory access violation
                    #     continue_flag = DBG_EXCEPTION_NOT_HANDLED

                kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                            debug_event.dwThreadId,
                                            continue_flag)
        except EOFError:
            break
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    pid = input("pid: ")
    detector(pid)
