from ctypes import *
import time

msvcrt = cdll.msvcrt
counter = 0
msvcrt.printf('Loop iteration %d\n' % counter)
while 1:
    msvcrt.printf('Loop iteration %d\n' % counter)
    time.sleep(2)
    counter += 1
