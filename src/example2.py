import sys, os
import struct

def send(payload):
    sz = len(payload)
    header= struct.pack("!h", sz)
    return sys.stdout.write( header + payload )

def main_loop():
    while True:
        send(struct.pack('!B', 100))
    return None

if __name__ == '__main__':
    main_loop()