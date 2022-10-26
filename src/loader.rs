use core::ffi::c_void;
use std::ffi::CStr;
use crate::error::AppError;
use  windows::core::PCSTR;
use crate::user_struct::*;
use windows::Win32::UI::WindowsAndMessaging::WNDENUMPROC;
use windows::Win32::Foundation::{GetLastError, LPARAM};
use windows::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use ntapi::ntmmapi::NtUnmapViewOfSection;
use windows::Win32::System::Memory::*;
use windows::Win32::UI::WindowsAndMessaging::EnumThreadWindows;

// Calculate Checksum
fn __calculate_checksum(buff: &[u8]) -> u32 {
    let mut chksum = 0u32;
    for i in 0..buff.len() {
        chksum = (buff[i] as u32)
            .wrapping_mul(i as u32)
            .wrapping_add(chksum / 3);
    }
    chksum
}


// Print In Hex
fn __print_hex(buff: &Vec<u8>) {
    print!("======================= PE HEADERS =======================");
    let mut j: u32 = 0;
    let mut k: u32 = 0;
    for i in 0..buff.len(){
        if k%16==0{
            println!();
        }
        if j%4==0 && k%16 == 0 {
            print!("0x");
        }
        if j%4==0 && k%16 != 0{
            print!("\t0x");
        }
        
        print!("{:02x}", buff[i]);
        j = j + 1;
        k = k + 1;
        if i > 254 {break;}
    }
    println!();
    println!("==========================================================");
}


// Return Data Directory for executable
fn __fetch_data_dir(pe_header: &PeHeaders, dir_id: IMAGE_DIRECTORY_ENTRY) -> Result<IMAGE_DATA_DIRECTORY, AppError> {
    let nt_hdr = pe_header.nt_hdr;
    let optional_hdr = nt_hdr.OptionalHeader;
    let data_directory: IMAGE_DATA_DIRECTORY;
    let dir_index: usize = dir_id.0 as usize;

    if dir_id.0 >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
        return Err(AppError {description: String::from("Invalid Directory Entry Count")});
    }

    // Get Directory Entries
    println!("[i] Fetching Data Directory Entry: {}", dir_index);
    data_directory = optional_hdr.DataDirectory[dir_index];
    

    if data_directory.VirtualAddress == 0 {
        return Err(AppError {description: String::from("Directory Entry Virtual Address is empty")})
    }

    Ok(data_directory)
}


// // Fix Import Address Table
fn __fix_iat(imgbaseptr:u64, module_ptr: Vec<u8>) -> Result<(), AppError> {
    // Closure to find LoadLibraryA value
    let __load_library = |lib_to_load: String| {
        let mut vec_to_load:Vec<u8> = lib_to_load.as_bytes().to_vec();
        vec_to_load.push(0);
        let lib_addr = unsafe{LoadLibraryA(PCSTR(vec_to_load.as_ptr() as *const u8))};
        lib_addr
    };

    let mut pe_hdrs: PeHeaders = PeHeaders::new();
    match pe_hdrs.populate(module_ptr){
        Ok(_val) => _val,
        Err(e) => {
            return Err(e);
        }
    };
    
    let imports_dir: IMAGE_DATA_DIRECTORY = match __fetch_data_dir(&pe_hdrs, IMAGE_DIRECTORY_ENTRY_IMPORT) {
        Ok(val) => val,
        Err(e) => {
            return Err(e);
        }
    };
    
    let virtual_addr = imports_dir.VirtualAddress as usize;
    let max_size = imports_dir.Size as usize;


    let mut parsed_size: usize = 0;
    while parsed_size < max_size {
        // lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);
        let _offset = virtual_addr + parsed_size + imgbaseptr as usize;
        let lib_desc: IMAGE_IMPORT_DESCRIPTOR = unsafe {std::ptr::read(_offset as *const IMAGE_IMPORT_DESCRIPTOR)};
        unsafe{
            if lib_desc.Anonymous.OriginalFirstThunk == 0 && lib_desc.FirstThunk == 0 {
                break;
            }
        }

        let _offset = imgbaseptr as usize + lib_desc.Name as usize;
        // let lib_name = std::ptr::read(_offset as *const u8); 
        // let lib_name = match std::str::from_utf8(&lib_name) {
        //     Ok(res) => res,
        //     Err(e) => {
        //         return Err(AppError{description:String::from("Failed to get lib_name")});
        //     }
        // };
        let lib_name = unsafe { CStr::from_ptr(_offset as *const i8).to_str().unwrap().to_owned() };
        println!("[i] Library\t{}", lib_name);
        let call_via = lib_desc.FirstThunk as usize;
        let mut thunk_addr = unsafe { lib_desc.Anonymous.OriginalFirstThunk as usize};
        
        if thunk_addr == 0 {
            thunk_addr = lib_desc.FirstThunk as usize;
        }

        let offset_field = 0;
        let offset_thunk = 0;
        loop {
            let mut field_offset = offset_field + call_via + imgbaseptr as usize;
            let mut orign_offset = offset_thunk + thunk_addr + imgbaseptr as usize;
            let mut field_thunk = unsafe {std::ptr::read(field_offset as *const IMAGE_THUNK_DATA64)};
            let orign_thunk = unsafe {std::ptr::read(orign_offset as *const IMAGE_THUNK_DATA64)};
            let orign_ordinal = unsafe{orign_thunk.u1.Ordinal};

            if 0 != (orign_ordinal & IMAGE_ORDINAL_FLAG64) {
                let libr_addr = match __load_library(lib_name.clone()){
                    Ok(val) => val,
                    Err(e) => {
                        let err = format!("Error Occured as: {} {:?}",e, unsafe{GetLastError()});
                        return Err(AppError{description: err});
                    }
                };
                
                let mut lprocvec: Vec<u8> = unsafe{ CStr::from_ptr(orign_ordinal as *const i8).to_str().unwrap().to_owned().clone().as_bytes().to_vec() };
                lprocvec.push(0);
                let lprocname: PCSTR = PCSTR(lprocvec.as_ptr() as *const u8); 
                let addr = match unsafe{GetProcAddress(libr_addr, lprocname)} {
                    Some(val) => val as u64,
                    None => {
                        let err = format!("GetProcAddress() failed with error: {:?}", unsafe{GetLastError()});
                        return Err(AppError{description: err});
                    },
                };
                field_thunk.u1.Function = addr;
                continue;
            }

            unsafe{        
                if field_thunk.u1.Function == 0 {
                    break;
                }
            }

            unsafe {
                if field_thunk.u1.Function == orign_thunk.u1.Function {
                    let _offset = imgbaseptr + orign_thunk.u1.AddressOfData;
                    let by_name: IMAGE_IMPORT_BY_NAME = std::ptr::read(_offset as *const IMAGE_IMPORT_BY_NAME);

                    println!("[i] Name:\t\t{:?}", by_name.Name);
                    println!("{:?}", by_name);
                }
            }

            orign_offset = orign_offset + std::mem::size_of::<IMAGE_THUNK_DATA64>();
            field_offset = field_offset + std::mem::size_of::<IMAGE_THUNK_DATA64>();
            break;
        }

        parsed_size = parsed_size + std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    };
    Ok(())
}



// Run PE file
pub fn load_pe(pe_buf: Vec<u8>)->Result<(), AppError> {
    let mut pe_headers: PeHeaders = PeHeaders::new();

    // Populate Headers
    match pe_headers.populate(pe_buf.clone()) {
        Ok(_res) => _res,
        Err(e) => {
            return Err(e);
        }
    }
    
    let mut nt_hdr = pe_headers.nt_hdr;
    let section_hdr_arr = pe_headers.section_hdr_arr.clone();
    // Print Headers
    // pe_headers.print_headers();
    
    // // PE checksum 
    // {
    //     checksum = __calculate_checksum(&pe_buf);
    // }
    // println!("[i] Checksum: {}", checksum);

    println!("[i] PE Size: {}", pe_buf.len());
    
    // Fetch BaseRelocation Table Address
    let _reloc_dir = match __fetch_data_dir(&pe_headers, IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        Ok(val) => val,
        Err(e) => {
            return Err(e);
        }
    };
    println!("[i] Fetched BaseRelocation Table Address");
    let preferaddr = nt_hdr.OptionalHeader.ImageBase;
    
    // Unmap memory
    {
        let _process_handle: *mut ntapi::winapi::ctypes::c_void = (-1i32) as *mut ntapi::winapi::ctypes::c_void;
        let _base_addr: *mut ntapi::winapi::ctypes::c_void = preferaddr as *mut ntapi::winapi::ctypes::c_void;
        unsafe {
            NtUnmapViewOfSection(_process_handle, _base_addr);
        }
    }

    println!("[i] Trying to Allocate Memory");
    // Allocate Memory
    let pimagebase = unsafe{
        let mut _pimagebase = VirtualAlloc(
            Some(preferaddr as *const c_void),
            nt_hdr.OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE
        );
    
        if 0 == _pimagebase as u32{  
            _pimagebase = VirtualAlloc(
                    Some(std::ptr::null() as *const c_void),
                    nt_hdr.OptionalHeader.SizeOfImage as usize,
                    MEM_COMMIT | MEM_RESERVE, 
                    PAGE_EXECUTE_READWRITE
                );
            
            if 0 == _pimagebase as u32 {
                    return Err( AppError {description: format!("VirtualAlloc() failed: {:?}", GetLastError())});
                }
            }
        
        // let __pimagebase = _pimagebase as *const u8;
        // std::slice::from_raw_parts(__pimagebase, nt_hdr.OptionalHeader.SizeOfImage as usize)
        _pimagebase // *mut c_void
    };
    
    println!("[i] VirtualAlloc() Address\t{:p}", pimagebase);
    println!("[i] Source Address\t\t{:p}", pe_buf.as_ptr());
    println!("[i] Filling memory block with PE Data");

    nt_hdr.OptionalHeader.ImageBase = pimagebase as u64;

    unsafe {
        std::ptr::copy_nonoverlapping(
            pe_buf.as_ptr(), 
            pimagebase as *mut u8, 
            nt_hdr.OptionalHeader.SizeOfHeaders as usize 
        );
    }

    // let __pimagebase = pimagebase as *const u8;
    // let mut  _new_arr = unsafe {Vec::from(std::slice::from_raw_parts(__pimagebase, nt_hdr.OptionalHeader.SizeOfImage as usize)) };
    println!("[i] Filling Section Headers");
    for section_hdr in section_hdr_arr {
        let vir_addr = section_hdr.VirtualAddress;
        let ptr_raw_data = section_hdr.PointerToRawData as usize;
        let size_to_copy = section_hdr.SizeOfRawData as usize;
        let src = (pe_buf.as_ptr() as u64 + u64::try_from(ptr_raw_data).unwrap_or(ptr_raw_data as u64)) as *const u8;
        let dst = (pimagebase as u64 + u64::try_from(vir_addr).unwrap_or(vir_addr as u64)) as *mut u8;

        println!("[i] Copying {} Section from {:p}->{:p}", String::from_utf8_lossy(&section_hdr.Name), src, dst);
        
        unsafe {
            std::ptr::copy_nonoverlapping(
                src,
                dst,
                size_to_copy
            )
        } 
    }

    let ret_vec = unsafe{
        std::slice::from_raw_parts(pimagebase as *const u8, 
            nt_hdr.OptionalHeader.SizeOfHeaders as usize).to_vec()
        };

    match __fix_iat(pimagebase as u64, ret_vec){
        Ok(_res) => _res,
        Err(e) => {
            eprintln!("[!] Failed to fix IAT");
            return Err(e);
        }
    };
    println!("[i] Fixed IAT");

    let retaddr = pimagebase as u64 
                    + u64::try_from(nt_hdr.OptionalHeader.AddressOfEntryPoint)
                    .unwrap_or(nt_hdr.OptionalHeader.AddressOfEntryPoint as u64);
    


    let fn_pointer: WNDENUMPROC = unsafe { std::mem::transmute(retaddr) };
    let res = unsafe {EnumThreadWindows(0u32,fn_pointer,LPARAM(0)) };
    if !res.as_bool() {
        return Err( AppError{description: String::from("EnumThreadWindow() Failed")});
    }
    Ok(())
}