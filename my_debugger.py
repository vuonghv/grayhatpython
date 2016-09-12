from ctypes import *
from my_debugger_defines import *


kernel32 = windll.kernel32


class debugger():

    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False
        self.h_thread = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.breakpoints = {}
        self.first_breakpoint = True

    def load(self, path_to_exe):

        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want
        # to see the calculator GUI
        creation_flags = DEBUG_PROCESS

        startup_info = STARTUPINFO()
        process_info = PROCESS_INFOMATION()

        # The following two options allow the started process
        # to be shown as a separate window. This also illustrates
        # how different settings in the STARTUPINFO struct can affect
        # the debuggee.
        startup_info.dwFlags = 0x01
        startup_info.wShowWindow = 0x00

        startup_info.cb = sizeof(startup_info)

        success = kernel32.CreateProcessA(path_to_exe, None, None, None, None,
                                          creation_flags, None, None,
                                          byref(startup_info), byref(process_info))
        if success:
            print '[*] We have successfully launched the process!'
            print '[*] PID: %d' % process_info.dwProcessId
            self.debugger_active = True
            self.pid = process_info.dwProcessId
            self.h_process = self.open_process(process_info.dwProcessId)
        else:
            print '[*] Error: 0x%08x' % kernel32.GetLastError()

    def open_process(self, pid):
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return h_process

    def attach(self, pid):
        self.h_process = self.open_process(pid)

        # Attempt to attach to the process
        # if this fails we exit the call
        success = kernel32.DebugActiveProcess(pid)
        if success:
            self.debugger_active = True
            self.pid = int(pid)
        else:
            print '[*] Unable to attach to the process.'

    def run(self):
        # Now we have to poll the debuggee for debugging events
        while self.debugger_active:
            self.get_debug_event()

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            # Obtain the thread and context information
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(self.h_thread)
            print 'Event Code: %d Thread ID: %d' % (
                debug_event.dwDebugEventCode,
                debug_event.dwThreadId
            )

            # If the event code is an exception, we want to examine it further
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                # Obtain the exception code
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print 'Access Violation Detected.'
                elif self.exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    print 'Guard Page Access Detected.'
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    print 'Single Stepping.'

            kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                        debug_event.dwThreadId,
                                        continue_status)

    def exception_handler_breakpoint(self):
        print '[*] Inside the breakpoint handler.'
        print 'Exception Address: 0x%08x' % self.exception_address
        # Check if the breakpoint is one that we set
        if self.exception_address not in self.breakpoints:
            # If it is the first Windows driven breakpoint
            # then let's just continue on
            if self.first_breakpoint:
                self.first_breakpoint = False
                print '[*] Hit the first breakpoint.'
                return DBG_CONTINUE
        else:
            print '[*] Hit user defined breakpoint.'
            # This is where we handle the breakpoint we set
            # first put the original byte back
            self.write_process_memory(self.exception_address,
                                      self.breakpoints[self.exception_address])

            # Obtain a fresh context record, reset EIP back to the
            # original byte and the set the thread's context record
            # with the new EIP value
            self.context = self.get_thread_context(h_thread=self.h_thread)
            self.context.Eip -= 1
            kernel32.SetThreadContext(self.h_thread, byref(self.context))
        return DBG_CONTINUE

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print '[*] Finished debugging. Exiting....'
            return True
        else:
            print 'There was an error'
            return False

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if h_thread is None:
            print '[*] Could not obtain a valid thread handle.'
            return False
        return h_thread

    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot is None:
            return False

        # You have to set the size of the struct or the call will fail
        thread_entry.dwSize = sizeof(thread_entry)
        success = kernel32.Thread32First(snapshot, byref(thread_entry))

        while success:
            if thread_entry.th32OwnerProcessID == self.pid:
                thread_list.append(thread_entry.th32ThreadID)
            success = kernel32.Thread32Next(snapshot, byref(thread_entry))

        kernel32.CloseHandle(snapshot)
        return thread_list

    def get_thread_context(self, thread_id=None, h_thread=None):
        if thread_id is None and h_thread is None:
            raise ValueError('One of thread_id or h_thread must not be None')
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # Obtain a handle to the thread
        if h_thread is None:
            h_thread = self.open_thread(thread_id)
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        return False

    def read_process_memory(self, address, length):
        data = ''
        read_buf = create_string_buffer(length)
        count = c_ulong(0)

        if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
            return False
        data += read_buf.raw
        return data

    def write_process_memory(self, address, data):
        count = c_ulong(0)
        length = len(data)
        c_data = c_char_p(data[count.value:])
        if kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
            return True
        return False

    def bp_set(self, address):
        if address in self.breakpoints:
            return True
        try:
            # Store the original byte
            original_byte = self.read_process_memory(address, 1)

            # write the INT3 opcode
            if self.write_process_memory(address, '\xCC'):
                # Register the breakpoint in our internal list
                self.breakpoints[address] = (original_byte)
                return True
            print 'Cannot write_process_memory at 0x%08x, Error: 0x%08x' % (
                address, kernel32.GetLastError())
            return False
        except Exception as ex:
            print ex
            return False

    def func_resolve(self, dll, function):
        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)
        kernel32.CloseHandle(handle)
        return address