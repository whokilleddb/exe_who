//use url::Url;
use ctrlc;
use clap::Parser;

/// User defined modules
mod user_struct;

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
   
    set_ctrl_c_handler(cmd_options.quiet);
    println!("{}", cmd_options);
}
