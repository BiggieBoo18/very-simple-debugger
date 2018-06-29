import re
from ctypes                            import *
from defines                           import *
from privilege                         import set_debug_privilege
from prompt_toolkit                    import prompt
from prompt_toolkit.completion         import WordCompleter
from prompt_toolkit.patch_stdout       import patch_stdout
from process                           import open_process, enum_processes, attach, dettach
from module                            import enum_modules
from memory                            import read_process_memory, write_process_memory
from proc_address                      import get_func_address
from detector                          import detector

# set privilege for debug
set_debug_privilege()

# completion words
cmd_list = ["help", "processes", "modules", "function", "search", "attach", "dettach", "run", "bp", "del", "quit", "exit"]
words = WordCompleter(cmd_list, ignore_case=True)

class Debugger:
    def __init__(self):
        self.space_pattern = re.compile("\s+")
        self.quit_pattern  = re.compile("^(exit|quit)$", re.IGNORECASE)
        self.attached_pid  = None
        self.h_process     = None
        self.sw_bps        = {}

    def run(self):
        while True:
            processes = enum_processes()
            if not processes:
                self.show_winerror()
                return False
            pids = [str(pid) for pid, _ in processes]
            words = WordCompleter(cmd_list+pids, ignore_case=True)
            try:
                cmd = prompt(
                    "(vsdb)> ",
                    completer=words,
                    complete_while_typing=True,
                    )
            except EOFError:
                # print("[*] You pressed Ctrl-D")
                break
            except KeyboardInterrupt:
                # print("[*] You pressed Ctrl-C")
                break
            if self.quit_pattern.search(cmd):
                break
            self.command_executer(cmd)
        if self.attached_pid:
            self.del_all_sw_bps()
            self.dettach_process(self.attached_pid)
        print("[*] Debugger Quit")

    def command_executer(self, cmd):
        def command_parser(cmd):
            tmp = self.space_pattern.sub(" ", cmd).split(" ")
            return [c for c in tmp if c]
        cmd = command_parser(cmd)
        if not cmd:
            return False
        elif cmd[0]=="help": # help
            for c in cmd_list:
                print(c)
        elif cmd[0]=="processes": # processes
            self.show_processes()
        elif cmd[0]=="modules": # modules [<module name>]
            if self.attached_pid:
                if len(cmd)>=2:
                    self.show_modules(cmd[1])
                else:
                    self.show_modules()
            else:
                print("[!!] Process is not attached!")
        elif cmd[0]=="function": # function <module name> <function name>
            if self.attached_pid:
                if len(cmd)>=3:
                    self.show_function(cmd[1], cmd[2])
                else:
                    print("[!!] Process is not attached!")
            else:
                print("[!!] Process is not attached!")
        elif cmd[0]=="search": # search <name or pid>
            if len(cmd)>=2:
                self.search_process(cmd[1])
        elif cmd[0]=="attach": # attach <pid>
            if len(cmd)>=2:
                try:
                    if self.attached_pid:
                        self.dettach_process(self.attached_pid)
                    if self.attach_process(int(cmd[1])):
                        self.attached_pid = int(cmd[1])
                except ValueError:
                    print("[!!] Please enter 'help'")
            else:
                print("[!!] Please enter 'help'")
        elif cmd[0]=="dettach": # dettach [<pid>]
            if len(cmd)>=2:
                try:
                    if self.dettach_process(int(cmd[1])):
                        self.attached_pid = None
                except ValueError:
                    print("[!!] Please enter 'help'")
            else:
                if self.attached_pid:
                    self.dettach_process(self.attached_pid)
                    self.attached_pid = None
        elif cmd[0]=="run": # run
            if self.attached_pid:
                self.run_detector()
            else:
                print("[!!] Process is not attached!")
        elif cmd[0]=="bp": # bp <address>
            if self.attached_pid:
                if len(cmd)>=2:
                    self.set_sw_bp(cmd[1])
                else:
                    print("[!!] Please enter 'help'")
            else:
                print("[!!] Process is not attached!")
        elif cmd[0]=="del": # del <index>
            if self.attached_pid:
                if len(cmd)>=2 and cmd[1].isdigit():
                    self.del_sw_bp(int(cmd[1]))
                else:
                    print("[!!] Please enter 'help'")
            else:
                print("[!!] Process is not attached!")

    def show_processes(self):
        processes = enum_processes()
        if not processes:
            self.show_winerror()
            return False
        for pid, fname in processes:
            print("[{}]:{}".format(pid, fname))

    def show_modules(self, module_name=""):
        modules = enum_modules(self.attached_pid)
        if module_name:
            for m in modules:
                if m["szModule"]==module_name.encode():
                    print("PID:         {}".format(m["th32ProcessID"]))
                    print("MID:         {}".format(m["th32ModuleID"]))
                    print("ADDRESS      0x{:016X}".format(m["modBaseAddr"]))
                    print("MODULE_NAME: {}".format(m["szModule"].decode()))
                    print("MODULE_PATH: {}".format(m["szExePath"].decode()))
        else:
            for m in modules:
                print("PID:         {}".format(m["th32ProcessID"]))
                print("MID:         {}".format(m["th32ModuleID"]))
                print("ADDRESS:     0x{:016X}".format(m["modBaseAddr"]))
                print("MODULE_NAME: {}".format(m["szModule"].decode()))
                print("MODULE_PATH: {}".format(m["szExePath"].decode()))

    def show_function(self, module_name, func_name):
        address = get_func_address(module_name, func_name.encode())
        if not address:
            self.show_winerror()
            return False
        print("MODULE_NAME:   {}".format(module_name))
        print("FUNCTION_NAME: {}".format(func_name))
        print("ADRESS:        0x{:016X}".format(address))

    def search_process(self, text):
        processes = enum_processes()
        for pid, fname in processes:
            if text.lower() in str(pid) or text.lower() in fname.lower():
                print("[{}]:{}".format(pid, fname))

    def attach_process(self, pid):
        if not attach(pid):
            self.show_winerror()
            return False
        self.h_process = open_process(pid)
        if not self.h_process:
            self.show_wineeror()
            return False
        return True

    def dettach_process(self, pid):
        if not dettach(pid):
            self.show_winerror()
            return False
        return True

    def run_detector(self):
        detector(self.h_process, self.sw_bps)

    def set_sw_bp(self, address):
        if not address[:2]=="0x":
            print("[!!]Addres is invalid")
            return False
        p_address = cast(int(address, 16), POINTER(BYTE))
        if address not in [v[0] for v in self.sw_bps.values()]:
            original_byte = read_process_memory(self.h_process, p_address, 1)
            if not original_byte:
                self.show_winerror()
                return False
            if not write_process_memory(self.h_process, p_address, "\xCC"):
                self.show_winerror()
                return False
            self.sw_bps[len(self.sw_bps)] = (address, original_byte)
            return True
        return False

    def del_sw_bp(self, index):
        if index not in self.sw_bps:
            print("[!!]Index is invalid")
            return False
        p_address     = cast(int(self.sw_bps[index][0], 16), POINTER(BYTE))
        original_byte = self.sw_bps[index][1]
        if original_byte[:2]!="0x":
            original_byte = hex(ord(original_byte))
        if not write_process_memory(self.h_process, p_address, original_byte):
            self.show_winerror()
            return False
        return True

    def del_all_sw_bps(self):
        for break_info in self.sw_bps.values():
            p_address     = cast(int(break_info[0], 16), POINTER(BYTE))
            original_byte = break_info[1]
            if original_byte[:2]!="0x":
                original_byte = hex(ord(original_byte))
            if not write_process_memory(self.h_process, p_address, original_byte):
                self.show_winerror()
                return False
        return True
            

    def show_winerror(self):
        print(WinError(GetLastError()))

if __name__ == "__main__":
    dbg = Debugger()
    dbg.run()
