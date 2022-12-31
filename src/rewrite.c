/// Rewriting WinAPI functions
/// References: https://wiki.osdev.org/PE
#include "rewrite.h"

typedef HMODULE (WINAPI * LoadLibrary_t)(LPCSTR lpFileName);
extern LoadLibrary_t pLoadLibraryA = NULL;

HMODULE WINAPI __get_module_handle(LPCSTR lpModuleName){   
    wchar_t __lib_nameW[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, lpModuleName, -1, __lib_nameW, MAX_PATH); 

    // get the offset of Process Environment Block
    #ifdef _M_IX86 
        PEB * peb_blk = (PEB *) __readfsdword(0x30);    // for 32 bit, the address of PEB is stored at an offset of 0x30 in the fs register
    #else
        PEB * peb_blk = (PEB *) __readgsqword(0x60);     // for 64 bit, the address of PEB is stored at an offset of 0x60 in the gs register
    #endif

    #ifdef VERBOSE
        if(lpModuleName) 
            printf("\n[i] %s\n", lpModuleName);
        else
            printf("\n[i] Self Process\n");
        printf("0x%08x\t Process Environment Block\n");
    #endif


    // From MSDN: 
    // If this parameter is NULL, GetModuleHandle returns a handle to the file used to create the calling process (.exe file).
    if(NULL == lpModuleName)
        return (HMODULE) (peb_blk->ImageBaseAddress);
    
    PEB_LDR_DATA * __ldr = peb_blk->Ldr;
    LIST_ENTRY * __in_memory_order_module_list = &__ldr->InMemoryOrderModuleList; // Address of Beginning of Doubly Linked List
    LIST_ENTRY * __start_list_entry = __in_memory_order_module_list->Flink;

    #ifdef VERBOSE
        printf("0x%x\t Address of Loader\n", __ldr);
        printf("0x%x\t Address of InMemoryOrderModuleList\n", __in_memory_order_module_list);
    #endif

    // Iterate through Doubly Linked List
    for(LIST_ENTRY * _cell = __start_list_entry;                    // Initial Cell of InMemoryOrderModuleList
                     _cell != __in_memory_order_module_list;        // Iterate over all values of the Doubly Linked List
                     _cell = _cell->Flink){
        
        // Get Current Data Table Entry
        LDR_DATA_TABLE_ENTRY * _entry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *)_cell - sizeof(LIST_ENTRY)); 
        
        if (lstrcmpiW(__lib_nameW, _entry->BaseDllName.Buffer) == 0){
            #ifdef VERBOSE
                printf("0x%x\t Address of DLLBase\n", _entry->DllBase);
            #endif

            return (HMODULE) _entry->DllBase;   
        }
    }
    #ifdef VERBOSE
        printf("Could not find address for %ls\n", lpModuleName);
    #endif

    return NULL;
}


/// Rewrite of GetProcAddress
///
/// Retrieves the address of an exported function (also known as a procedure)
/// or variable from the specified dynamic-link library (DLL).
///
/// Returns:
/// If the function succeeds, the return value is the address of the exported function or variable.
/// If the function fails, the return value is NULL.
FARPROC WINAPI __get_proc_address(HMODULE hModule, LPCSTR  lpProcName){
    char * base_addr = (char *) hModule;
    void *retaddr = NULL;

    // Get Pointers to main headers/structures
    IMAGE_DOS_HEADER * __dos_hdr = (IMAGE_DOS_HEADER *) base_addr;
    IMAGE_NT_HEADERS * __nt_hdr = (IMAGE_NT_HEADERS *) (base_addr + __dos_hdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER * __optional_hdr = &__nt_hdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY * __export_data_dir = (IMAGE_DATA_DIRECTORY *)(&__optional_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY * export_dir_addr = (IMAGE_EXPORT_DIRECTORY *)(base_addr + __export_data_dir->VirtualAddress);

    // Resolve Address to Export Address Table
    DWORD * addr_eat = (DWORD *)(base_addr + export_dir_addr->AddressOfFunctions);
    // Resolve Address to Table of Function Names
    DWORD * addr_func_name_tbl = (DWORD *)(base_addr + export_dir_addr->AddressOfNames);
    // Resolve Address to Table of Ordinals
    WORD * addr_ord_tbl = (WORD *)(base_addr + export_dir_addr->AddressOfNameOrdinals);

    // Resolve Function by Ordinal
    if (((DWORD_PTR)lpProcName >> 16) == 0) {           // Check if the supplied argument is an Ordinal instead of a name(Right shift by 2 bytes. Ordinals are WORDs)
        WORD __ordinal  = (WORD) lpProcName & 0xFFFF;     // Mask the lower bits
        DWORD __base = export_dir_addr->Base;

    #ifdef VERBOSE
        printf("\n[i] Ordinal Number:\t\t\t\t%d\n", __ordinal);
    #endif

        // Check if ordinal is out of range
        if (__ordinal < __base || __ordinal >= __base + export_dir_addr->NumberOfFunctions)
            return NULL;

        // get the function virtual address = RVA + BaseAddr
        retaddr = (FARPROC)(base_addr + (DWORD_PTR)addr_eat[__ordinal - __base]);
    }

    // Resolve function by name
    else {
        #ifdef VERBOSE
            printf("\n[i] %s\n", lpProcName);
        #endif        
        
        for (DWORD i = 0; i < export_dir_addr->NumberOfNames; i++) {
            char * __temp_name = (char *)base_addr + (DWORD_PTR) addr_func_name_tbl[i];
            if (strcmp(lpProcName, __temp_name) == 0) {
                retaddr = (FARPROC)(base_addr + (DWORD_PTR)addr_eat[addr_ord_tbl[i]]);
                break;
            }
        }
    }

    #ifdef VERBOSE
        // Print relevant addresses
        printf("0x%x\tDOS Header Address\n",                __dos_hdr);
        printf("0x%x\tNT Header Address\n",                 __nt_hdr);
        printf("0x%x\tOptional Header Address\n",           __optional_hdr);
        printf("0x%x\tData Directory Address\n",            __export_data_dir);
        printf("0x%x\tExport Directory Address Start\n",    export_dir_addr);
        printf("0x%x\tExport Directory Address End\n",      export_dir_addr + __export_data_dir->Size);
        printf("0x%x\tExport Address Table Address\n",      addr_eat);
        printf("0x%x\tTable of Function Name Address\n", addr_func_name_tbl);
        printf("0x%x\tTable of Ordinals Address\n", addr_ord_tbl);
    #endif

    // Check if the VA is forwarded to another library function
    if ((char *)retaddr >= (char *)export_dir_addr &&
        (char *)retaddr < (char *)(export_dir_addr + __export_data_dir->Size)){
            HMODULE __lib_handle;
            
            char * __fwd_dll = _strdup((char *)retaddr);
            
            if (!__fwd_dll) return NULL;
            
            char * __fwd_func = strchr(__fwd_dll, '.');
            * __fwd_func = 0;               // Nullify the '.' at the beginning
            __fwd_func ++;                  // Point to the beginning of the name
            
            #ifdef VERBOSE
                printf("\n[i] %s -> %s.%s\n", lpProcName, __fwd_dll, __fwd_func);
            #endif

            // resolve LoadLibrary function pointer, keep it as global variable
            if (!pLoadLibraryA) {
                HMODULE __handle = __get_module_handle((LPCSTR)"kernel32.dll");
                if (NULL == __handle) {
                    free(__fwd_dll);
                    return NULL;
                }

                pLoadLibraryA= (LoadLibrary_t)__get_proc_address( __handle, "LoadLibraryA");
                if (pLoadLibraryA == NULL) {
                    free(__fwd_dll);
                    return NULL;
                }
            }

            // Load the external libraru
            __lib_handle = pLoadLibraryA(__fwd_dll);
            
            #ifdef VERBOSE
                printf("0x%x\tAddress of %s\n", __lib_handle, __fwd_dll);
            #endif

            free(__fwd_dll);
            if (!__lib_handle) return NULL;

            retaddr = __get_proc_address(__lib_handle,__fwd_func);
        }

    #ifdef VERBOSE
        if (!retaddr)
            fprintf(stderr, "Address of %s is NULL!\n\n", lpProcName);
        else
            printf("0x%x\tAddress of %s\n", retaddr, lpProcName);
    #endif
    return (FARPROC) retaddr;
}