// Taken from https://github.com/whokilleddb/functions-for-red-teamers/
#include <stdio.h>
#include <string.h>
#include <windows.h>
//#define VERBOSE 
#pragma once 

// Process Environment Block(PEB) Loader data Structure
// https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00063
typedef struct _PEB_LDR_DATA{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA;

// Unicode string
// https://processhacker.sourceforge.io/doc/ntbasic_8h_source.html#l00111
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;


// https://processhacker.sourceforge.io/doc/ntldr_8h_source.html#l00102
// Structure pointed by PEB_LDR_DATA->InMemoryOrderModuleList
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    BYTE Reserved[136-104];
} LDR_DATA_TABLE_ENTRY;


// Structure Representing Process Environment Block(PEB)
// https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00008
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN SpareBits : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA* Ldr;
    BYTE Reserved[712-32];
} PEB;
  
  
extern HMODULE WINAPI __get_module_handle(LPCSTR lpModuleName);
extern FARPROC WINAPI __get_proc_address(HMODULE hModule, LPCSTR  lpProcName);