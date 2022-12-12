//use url::Url;
use ctrlc;
use std::io;
use clap::Parser;
use std::io::Write;
use std::error::Error;

/// User defined modules
mod user_struct;

/// Function to get information interactive mode
fn interactive_mode_setup(cmd_line: &mut user_struct::CmdOptions) -> Result <(), Box<dyn Error>> {
    // Get User input
    let get_user_input = |msg: &str| {
        let mut buf: String = String::new();

        print!("[i] {}", msg);
        match io::stdout().flush(){
            Ok(_v) => _v,
            Err(e) => {
                eprintln!("[!] Error occured as: {}", e);
                return None;
            },
        };

        match io::stdin().read_line(&mut buf){
            Ok(_v) => _v,
            Err(e) => {
                eprintln!("[!] Error occured as: {}", e);
                return None;
            },
        };

        buf = buf.trim().to_string();
        Some(buf.clone())
    };

    // Closure to read user input and return a boolean to Y/N questions
    let get_choice = | msg: &str | {
        let user_input = get_user_input(msg).unwrap();
        let choice = match user_input.as_str().chars().next(){
            Some(_v) => {
                let ch = _v.to_ascii_uppercase();
                if ch == 'Y' {
                    true
                }
                else {
                    false
                }
            },
            None => false
        };
        choice
    };

    // Get URL
    loop {
        let _url = match get_user_input("Enter remote PE url: ") {
            Some(val) => val.to_string(),
            None => return Err("Failed to read remote PE URL!".into()),
        };

        if  !_url.is_empty() {
            cmd_line.url = _url;
            break;
        }
        eprintln!("[!] URL value cannot be empty!");
    }

    // Check for encryption
    cmd_line.enc = get_choice("Is the incoming binary encrypted?(y/N): ");

    // Get Key for Encryption
    if cmd_line.enc {
        loop {
            let _key = match get_user_input("Enter Decryption Key: ") {
                Some(val) => val.to_string(),
                None => return Err("Failed to read decryption key!".into()),
            };

            if  !_key.is_empty() {
                cmd_line.key = Some(_key);
                break;
            }
            eprintln!("[!] Key value cannot be empty!");
        }
    }

    // Patching and Detection
    cmd_line.patch_amsi = get_choice("Patch AMSI?(y/N): ");
    cmd_line.patch_amsi = get_choice("Patch ETW?(y/N): ");
    cmd_line.detect_sandbox = get_choice("Detect Sandbox?(y/N): ");

    // Get printing mode
    let printing_mode = get_user_input("Printing mode([n]ormal/[Q]uiet/[V]erbose):");
    match printing_mode.unwrap().as_str().chars().next(){
        Some(_v) => {
            let ch = _v.to_ascii_uppercase();
            if ch == 'V' {
                cmd_line.verbose = true;
                cmd_line.quiet = false;
            }
            else if ch == 'Q'{
                cmd_line.verbose = false;
                cmd_line.quiet = true;
            }
            else {
                cmd_line.verbose = false;
                cmd_line.quiet = false;
            }
        },
        None => {
            cmd_line.verbose = false;
            cmd_line.quiet = false;
        }
    };

    Ok(())
}


/// Ctrl-C Handler
fn set_ctrl_c_handler(quiet: bool) {
    // Set Ctrl-C handler
    match ctrlc::set_handler(move || {
        if !quiet {
            eprintln!("\n[i] Received Ctrl+C!");
        }
        std::process::exit(0);
    }){
        Ok(_r) => _r,
        Err(_e) => {
            if !quiet {
                eprintln!("\n[i] Failed to set control handler!");
            }
            std::process::exit(-1);
        }
    }
}


#[tokio::main]
async fn main(){
    let mut cmd_options = user_struct::CmdOptions::parse();
    if cmd_options.interactive {
        match interactive_mode_setup(&mut cmd_options){
            Ok(_v) => _v,
            Err(e) => {
                eprintln!("[!] Error occured as: {:?}", e);
                std::process::exit(-2);
            }
        };
    }
    println!("{}",cmd_options);
    set_ctrl_c_handler(cmd_options.quiet);

}
