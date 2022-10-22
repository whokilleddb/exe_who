use core::ffi::c_void;
use crate::error::AppError;
use crate::user_struct::*;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Diagnostics::Debug::*;
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
// fn __fix_iat(module_ptr: &[u8]) -> bool {
//     let lib_desc: IMAGE_IMPORT_DESCRIPTOR;
//     let import_dir: IMAGE_DATA_DIRECTORY = match __fetch_data_dir(module_ptr, IMAGE_DIRECTORY_ENTRY_IMPORT){
//         Ok(val) => val,
//         Err(e) => {
//             return false;
//         }
//     };

//     let maxsize: usize = import_dir.Size as usize;
//     let imp_va: u32 = import_dir.VirtualAddress;
    
//     let mut i: usize = 0;
//     let struct_size = std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
//     while i < maxsize {
//         lib_desc = 
//         i = i + struct_size;
//     }
//     true
// }



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

    let retaddr = pimagebase as u64 
                    + u64::try_from(nt_hdr.OptionalHeader.AddressOfEntryPoint)
                    .unwrap_or(nt_hdr.OptionalHeader.AddressOfEntryPoint as u64);
    
    // EnumThreadWindows(0u32,,LPARAM(0));

    Ok(())
}