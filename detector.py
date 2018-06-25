from ctypes    import *
from ctypes    import wintypes
from defines   import *
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

def sfw_bp_handler(exception_record):
    print("Not Implemented yet")

def detector(pid):
    first_break = False # windows break
    debug_event = DEBUG_EVENT()
    print("Please to quit the detector press Ctrl-C")
    while True:
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
                            sfw_bp_handler(exception_record)
                        else:
                            first_break = True # enable first windows break

                kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                            debug_event.dwThreadId,
                                            # DBG_EXCEPTION_NOT_HANDLED)
                                            DBG_CONTINUE)
        except EOFError:
            break
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    pid = input("pid: ")
    detector(pid)
