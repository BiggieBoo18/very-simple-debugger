import re
from ctypes                            import *                  
from privilege                         import set_debug_privilege
from prompt_toolkit                    import prompt
from prompt_toolkit.completion         import WordCompleter
from prompt_toolkit.patch_stdout       import patch_stdout
from process                           import enum_processes, attach, dettach
from module                            import enum_modules
from detector                          import detector

# set privilege for debug
set_debug_privilege()

# completion words
cmd_list = ["help", "processes", "modules", "search", "attach", "dettach", "run", "quit", "exit"]
words = WordCompleter(cmd_list, ignore_case=True)

class Prompt:
    def __init__(self):
        self.space_pattern = re.compile("\s+")
        self.quit_pattern  = re.compile("^(exit|quit)$", re.IGNORECASE)
        self.attached_pid  = None

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
                print("ADDRESS      0x{:016X}".format(m["modBaseAddr"]))
                print("MODULE_NAME: {}".format(m["szModule"].decode()))
                print("MODULE_PATH: {}".format(m["szExePath"].decode()))

    def search_process(self, text):
        processes = enum_processes()
        for pid, fname in processes:
            if text.lower() in str(pid) or text.lower() in fname.lower():
                print("[{}]:{}".format(pid, fname))

    def attach_process(self, pid):
        if not attach(pid):
            self.show_winerror()
            return False
        return True

    def dettach_process(self, pid):
        if not dettach(pid):
            self.show_winerror()
            return False
        return True

    def run_detector(self):
        detector(self.attached_pid)

    def show_winerror(self):
        print(WinError(GetLastError()))

if __name__ == "__main__":
    prm = Prompt()
    prm.run()
