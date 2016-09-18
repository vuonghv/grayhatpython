from ctypes import *


msvcrt = cdll.msvcrt

if __name__ == '__main__':
    # Give the debugger time to attach, then hit a button
    raw_input('Once the debugger is attached, press any key.')

    # Create the 5-bytes destination buffer
    buffer = c_char_p('AAAAA')

    # The overflow string
    overflow = 'A' * 100

    # Run the overflow
    msvcrt.strcpy(buffer, overflow)
