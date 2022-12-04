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
    print!("[i] Enter URL of remote PE: ");
    match io::stdout().flush(){
        Ok(_v) => _v,
        Err(e) => return Err(Box::new(e)),
    }; 
    io::stdin().read_line(&mut cmd_line.url).unwrap();
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
    set_ctrl_c_handler(cmd_options.quiet);

}
