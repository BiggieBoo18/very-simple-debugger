from ctypes    import *
from ctypes    import wintypes
from defines   import *
from privilege import set_debug_privilege
from prompt    import Prompt
from debugger  import Debugger

if set_debug_privilege():
    print("[*] enabled debug privilege")
else:
    print("[!!] Can't enable to debug privilege!")

