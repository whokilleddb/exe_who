#!/usr/bin/python3
from os import wait
import sys
import argparse


def encrypt_me(filename, keystr):
    new_filename = f"{filename}.bin"
    key = bytearray()
    key.extend(map(ord, keystr))
    fileb = bytearray()
    sizef = 0
    xor_byte_array = bytearray()

    try:
        fileb = bytearray(open(filename, 'rb').read())
        sizef = len(fileb)
        xor_byte_array = bytearray(sizef)

    except Exception as e:
        print(f"Exception occured as {e}", file=sys.stderr)
        return

    for i in range(sizef):
        xor_byte_array[i] = fileb[i] ^ key[i%len(keystr)]
    
    # Write Xor'd bytes to file
    try:
        open(new_filename, 'wb').write(xor_byte_array)
    except Exception as e:
        print(f"Exception occured as: {e}", file=sys.stderr)
        return

    print(f"Saved output to file: {new_filename}")


def main():
    parser = argparse.ArgumentParser(description="XOR Encrypt Your Files!")
    parser.add_argument('-f', '--file', required=True, help='File to Encrypt')
    parser.add_argument('-k', '--key', default='abcdefghik', help='String to Xor with')
    options = parser.parse_args()
    encrypt_me(options.file, options.key)

if __name__ == '__main__':
    main()
