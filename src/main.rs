//use url::Url;
use ctrlc;
use std::io;
use clap::Parser;
use std::io::Write;
use std::error::Error;

/// User defined modules
mod user_struct;

/// Function to get information interactive mode
fn get_interactive_mode(cmd_line: &mut user_struct::CmdOptions) -> Result <(), Box<dyn Error>> {
    // Closure to read user input and return a boolean to Y/N questions
    let _get_choice = | _user_input: String | {
        true
    };

    // Get User input 
    let user_input = |msg: &str| {
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

    // Get URL
    cmd_line.url = match user_input("Enter remote PE url: ") {
        Some(val) => val.to_string(),
        None => return Err("Failed to read remote PE URL!".into()),
    };

    // Check for encryption

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
        match get_interactive_mode(&mut cmd_options){
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
