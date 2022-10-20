use core::ffi::c_void;
use crate::error::AppError;
use crate::user_struct::*;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Diagnostics::Debug::*;
use ntapi::ntmmapi::NtUnmapViewOfSection;
use windows::Win32::System::Memory::*;

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
pub fn load_pe(mut pe_buf: Vec<u8>)->Result<(), AppError> {
    let mut pe_headers: PeHeaders = PeHeaders::new();

    // Populate Headers
    match pe_headers.populate(pe_buf.clone()) {
        Ok(_res) => _res,
        Err(e) => {
            return Err(e);
        }
    }
    
    let mut nt_hdr = pe_headers.nt_hdr;
    let _section_hdr_arr = pe_headers.section_hdr_arr.clone();

    // Print Headers
    pe_headers.print_headers();
    
    // // PE checksum 
    // {
    //     checksum = __calculate_checksum(&pe_buf);
    // }
    // println!("[i] Checksum: {}", checksum);

    println!("[i] PE Size: {}", pe_buf.len());
    
    // Fetch BaseRelocation Table Address
    let reloc_dir = match __fetch_data_dir(&pe_headers, IMAGE_DIRECTORY_ENTRY_BASERELOC) {
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
        let _pimagebase = VirtualAlloc(
            Some(preferaddr as *const c_void),
            nt_hdr.OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE
        );
    
        if _pimagebase.is_null(){    
            let _pimagebase = VirtualAlloc(
                    Some(std::ptr::null() as *const c_void),
                    nt_hdr.OptionalHeader.SizeOfImage as usize,
                    MEM_COMMIT | MEM_RESERVE, 
                    PAGE_EXECUTE_READWRITE
                );
            
            if _pimagebase.is_null() {
                    return Err( AppError {description: format!("VirtualAlloc() failed: {:?}", GetLastError())});
                }
            }
        
        // let __pimagebase = _pimagebase as *const u8;
        // std::slice::from_raw_parts(__pimagebase, nt_hdr.OptionalHeader.SizeOfImage as usize)
        _pimagebase // *mut c_void
    };
    
    // let section_arr = __get_section_hdr_arr(&pe_buf);
    println!("[i] Filling memory block with PE Data");

    nt_hdr.OptionalHeader.ImageBase = pimagebase as u32;
    unsafe {
        std::ptr::copy_nonoverlapping(
            pe_buf.as_mut_ptr(), 
            pimagebase as *mut u8, 
            nt_hdr.OptionalHeader.SizeOfHeaders as usize 
        );
    }
    
    // // Map Section header
    // let section_header_add: Vec<IMAGE_SECTION_HEADER> = 

    Ok(())
}
