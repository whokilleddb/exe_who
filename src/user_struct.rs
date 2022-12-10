//! This file contains all structs required by the program at various stages
use std::fmt;
use clap::Parser;
use std::option::Option;

/// Struct to store command line options
#[derive(Debug, Parser)]
#[command(name = "Exe who?")]
#[command(author = "whokilleddb <whokilleddb@proton.me>")]
#[command(version = "1.0")]
#[command(about = "Run Executables In-memory!", long_about = None)]
pub struct CmdOptions {
    /// Run in interactive mode
    #[arg(short, long)]
    pub interactive: bool,            

    /// Url to fetch executable from
    #[arg(short, long, conflicts_with = "interactive")]
    pub url: String,            
    
    /// Incoming executable is encrypted
    #[arg(short, long="encrypted", requires = "decrypt")]
    pub enc: bool,                      

    /// Key to be used for decryption
    #[arg(short, long, group = "decrypt")]
    pub key: Option<String>,            
    
    /// Patch AMSI
    #[arg(long="pa")]
    pub patch_amsi: bool,               
    
    /// Patch ETW
    #[arg(long="pe")]
    pub patch_etw: bool,                
    
    /// Detect Sandbox
    #[arg(short, long)]
    pub detect_sandbox: bool,           
    
    /// Print Minimal messages
    #[arg(short, long, conflicts_with = "verbose")]
    pub quiet: bool,               

    /// Print verbose messages
    #[arg(short, long, conflicts_with = "quiet")]
    pub verbose: bool              
}


/// Properly display values
impl fmt::Display for CmdOptions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printing_mode = {
            if self.quiet {
                "Quiet"
            }

            else if self.verbose {
                "Verbose"
            }

            else {
                "Normal"
            }
        };
        write!(f, "[i] URL: {:?}\n[i] Encrypted: {}\r\n[i] Decryption Key: {:?}\r\n[i] Patch AMSI: {}\r\n[i] Patch ETW: {}\r\n[i] Detect Sandbox: {}\r\n[i] Printing Mode: {}\r\n", self.url, self.enc, self.key, self.patch_amsi, self.patch_etw, self.detect_sandbox, printing_mode)
    }
}
