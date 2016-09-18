from pydbg import *
from pydbg.defines import *

import threading
import time
import sys


class snapshotter(object):

    def __init__(self, exe_path):
        self.exe_path = exe_path
        self.pid = None
        self.dbg = None
        self.running = True

        # Start the debugger thread, and loop until it sets the PID
        # of our target process
        pydbg_thread = threading.Thread(target=self.start_debugger)
        pydbg_thread.setDaemon(0)
        pydbg_thread.start()

        while self.pid is None:
            time.sleep(1)

        # We now have a PID and the target is running; let's get a
        # second thread running to do the snapshots
        monitor_thread = threading.Thread(target=self.monitor_debugger)
        monitor_thread.setDaemon(0)
        monitor_thread.start()

    def monitor_debugger(self):
        while self.running:
            command = raw_input("Enter; 'snap', 'restore' or 'quit'")
            command = command.lower().strip()

            if command == 'quit':
                print '[*] Exiting the snapshotter.'
                self.running = False
                self.dbg.terminate_process()

            elif command == 'snap':
                print '[*] Suspending all threads.'
                self.dbg.suspend_all_threads()

                print '[*] Obtaining snapshot.'
                self.dbg.process_snapshot()

                print '[*] Resuming operation.'
                self.dbg.resume_all_threads()

            elif command == 'restore':
                print '[*] Suspending all threads.'
                self.dbg.suspend_all_threads()

                print '[*] Restoring snapshot.'
                self.dbg.process_restore()

                print '[*] Resuming operation.'
                self.dbg.resume_all_threads()

    def start_debugger(self):
        self.dbg = pydbg()
        self.dbg.load(self.exe_path)
        self.pid = self.dbg.pid
        self.dbg.run()

if __name__ == '__main__':
    exe_path = 'C:\\WINDOWS\\System32\\calc.exe'
    snapshotter(exe_path)
