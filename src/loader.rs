use core::ffi::c_void;
use crate::error::AppError;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Diagnostics::Debug::*;
use ntapi::ntmmapi::NtUnmapViewOfSection;

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


// Fetch NT Headers
fn __get_nt_headers(buff: &[u8]) -> Result<IMAGE_NT_HEADERS32 , AppError> {
    let max_offset: i32 = 1024;
    let pe_offset: i32;
    let __index: usize;
    let dos_hdr: IMAGE_DOS_HEADER;
    let nt_hdr: IMAGE_NT_HEADERS32;
    let nt_hdr_vec: &[u8];

    // Check for NULL
    if buff.as_ptr().is_null() {
        return Err(AppError { description: String::from("Empty Buffer in __get_nt_headers()") });
    }

    // Check Size
    if buff.len() < 64 {
        return Err(AppError { description: String::from("Insuffcient Header Data") });
    }

    dos_hdr = unsafe { std::ptr::read(buff.as_ptr() as *const IMAGE_DOS_HEADER)};
    pe_offset = dos_hdr.e_lfanew;

    if pe_offset > max_offset {
        return Err(AppError { description: String::from("Size of e_lfanew > 1024") });
    }

    __index = usize::try_from(pe_offset).unwrap_or(pe_offset as usize);
    nt_hdr_vec = &buff[__index..];

    nt_hdr = unsafe { std::ptr::read(nt_hdr_vec.as_ptr() as *const IMAGE_NT_HEADERS32)};
    if nt_hdr.Signature != IMAGE_NT_SIGNATURE {
        return Err(AppError { description: String::from("Invalid NT Header Signature") });
    }

    Ok(nt_hdr.clone())
}


// Return Data Directory for executable
fn __fetch_data_dir(buff: &[u8], dir_id: IMAGE_DIRECTORY_ENTRY) -> Result<IMAGE_DATA_DIRECTORY, AppError> {
    let nt_hdr: IMAGE_NT_HEADERS32;
    let optional_hdr: IMAGE_OPTIONAL_HEADER32;
    let data_directory: IMAGE_DATA_DIRECTORY;
    let dir_index: usize = dir_id.0 as usize;

    if dir_id.0 >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
        return Err(AppError {description: String::from("Invalid Directory Entry Count")});
    }

    // Get NT Headers
    nt_hdr = match __get_nt_headers(buff){
        Ok(val)=>val,
        Err(e) => {
            return Err(e);
        },
    }; 

    // Get Optional Headers
    optional_hdr = nt_hdr.OptionalHeader;
    //println!("{:#?}", optional_hdr);
    // Get Directory Entries
    println!("[i] Fetching Data Directory Entry: {}", dir_index);
    data_directory = optional_hdr.DataDirectory[dir_index];
    

    if data_directory.VirtualAddress == 0 {
        return Err(AppError {description: String::from("Directory Entry Virtual Address is empty")})
    }

    Ok(data_directory)
}


// Run PE file
pub fn load_pe(mut pe_buf: Vec<u8>)->Result<(), AppError> {
    let checksum: u32;
    let _size: usize = pe_buf.len();
    let image_nt_headers: IMAGE_NT_HEADERS32;
    let reloc_dir: IMAGE_DATA_DIRECTORY;
    
    // local Scope 
    {
        checksum = __calculate_checksum(&pe_buf);
    }
    
    // Check for PE signature
    if pe_buf[0] != 77 && pe_buf[1] != 90 {
        return Err(AppError{description: String::from("Invalid PE Signature")});
    }

    println!("[i] PE Size: {}", pe_buf.len());
    println!("[i] Checksum: {}", checksum);

    // Fetch NT headers    
    image_nt_headers =  match __get_nt_headers(&pe_buf){
        Ok(val)=>val,
        Err(e) => {
            return Err(e);
        },
    }; 
    
    println!("[i] Fetched NT Headers");
    
    // Fetch BaseRelocation Table Address
    reloc_dir = match __fetch_data_dir(&pe_buf, IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        Ok(val) => val,
        Err(e) => {
            return Err(e);
        }
    };
    println!("[i] Fetched BaseRelocation Table Address");
    
    // Unmap memory
    // {
    //     let _process_handle: *mut c_void = &mut (-1);
    //     let _base_addr: *mut c_void = &mut (image_nt_headers.OptionalHeader.ImageBase);
    //     unsafe {
    //         NtUnmapViewOfSection1(_process_handle, _base_addr);
    //     }
    // }
    
   
    Ok(())
}