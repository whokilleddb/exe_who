// Definition of various WinAPI functions
#include <windef.h>
#pragma once

// XOR Function Key
const char XOR_FUNC_KEY[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
// Key for XOR strings
const char XOR_KEY[] = "abcdefghijklmnopqrstuvwxyz";
// Length of XOR Func key
unsigned int xor_func_key_len = (int)(sizeof(XOR_FUNC_KEY)/sizeof(XOR_FUNC_KEY[0]))-1;
// Length of xor key
unsigned int xor_key_len = (int)(sizeof(XOR_KEY)/sizeof(XOR_KEY[0]))-1;

// VirtualProtect
unsigned char __virtualprotect[] = {0x17, 0x2b, 0x31, 0x30, 0x30, 0x27, 0x2b, 0x18, 0x3b, 0x25, 0x3f, 0x29, 0x2e, 0x3a, 0x00};
typedef BOOL (__stdcall * __type_virtualprotect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
BOOL (WINAPI * _VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);