from ctypes import *
import time

msvcrt = cdll.msvcrt

if __name__ == '__main__':
    counter = 0
    while True:
        msvcrt.printf('Loop iteration %d\n' % counter)
        time.sleep(2)
        counter += 1
