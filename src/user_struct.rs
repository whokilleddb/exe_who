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
    #[arg(short, long, conflicts_with = "interactive", default_value_t=String::new())]
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

    /// [Experimental Feature] Save Payload in Clipboard Buffer
    #[arg(short='c', long="clipboard")]
    pub use_clipboard: bool,  

    /// Move executable to AppData
    #[arg(short='m', long="move")]
    pub move_exe: bool,
    
    /// Location to be moved to 
    #[arg(short, long)]
    pub location: Option<String>,

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

        let mut msg = format!("[i] URL:\t\t\t{}\r\n", self.url);
        msg = format!("{}[i] Encrypted:\t\t\t{}\r\n",msg, self.enc);
        if self.enc {
            let dec_key = match &self.key {
                Some(v) => v.as_str(),
                None => "None"
            };
                
            msg = format!("{}[i] Decryption Key:\t\t{}\r\n", msg, dec_key);
        }
        msg = format!("{}[i] Patch AMSI:\t\t\t{}\r\n",msg, self.patch_amsi);
        msg = format!("{}[i] Patch ETW:\t\t\t{}\r\n",msg, self.patch_etw);
        msg = format!("{}[i] Detect Sandbox:\t\t{}\r\n",msg, self.detect_sandbox);
        msg = format!("{}[i] Printing Mode:\t\t{}\r\n", msg, printing_mode);
        msg = format!("{}[i] Use Clipboard Buffer:\t{}\r\n", msg, self.use_clipboard);
        
        if self.move_exe {
            let move_path: &str = match &self.location {
                Some(v) => v.as_str(),
                None => "None"
            };    
            msg = format!("{}[i] Move Binary To:\t\t{}\r\n", msg, move_path);
        }

        write!(f, "{}", msg)
    }
}
