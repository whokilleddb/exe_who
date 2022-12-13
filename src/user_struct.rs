#![allow(dead_code)]
use url::Url;
use std::fmt;
use clap::ArgMatches;
use std::error::Error;
use std::option::Option;

/// Struct to store options 
#[derive(Clone)]
pub struct LoaderOptions {
    url: Url,
    verbosity: u32,
    patch_amsi: bool,
    patch_etw: bool,
    detect_sandbox: bool,
    key: Option<String>
}

/// Dictate how the contents of the struct will be printed
impl fmt::Display for LoaderOptions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut msg = format!("[i] URL\t\t\t\t{}\r\n", self.url);
        msg = format!("{}[i] Verbosity Level\t\t{}\r\n", msg, match self.verbosity {
            0 => "Quiet",
            1 => "Normal",
            2u32..=u32::MAX => "Verbose"
        });
        msg = format!("{}[i] AMSI Patching\t\t{}\r\n", 
                      msg,
                      match self.patch_amsi {
                          true => "ON",
                          false => "OFF"
                      });
        msg = format!("{}[i] ETW Patching\t\t{}\r\n",
                      msg,
                      match self.patch_etw {
                          true => "ON",
                          false => "OFF"
                      });
        msg = format!("{}[i] Sandbox Detection\t\t{}\r\n",
                      msg,
                      match self.detect_sandbox {
                          true => "ON",
                          false => "OFF"
                      });
        write!(f,"{}",msg)
    }
}

/// Implement various traits for LoaderOptions
impl LoaderOptions {
    /// Return new LoaderOptions struct
    pub fn new(cmds: ArgMatches) -> Result<LoaderOptions, Box<dyn Error>> {
        // Closure ton get bool flags for various loader options
        let check_bool = |option: &str|->bool {
            match cmds.get_one::<bool>(option) {
                Some(v) => *v,
                None => false
            }
        };

        // Get url of the endpoint
        let url: Url = match cmds.get_one::<String>("url"){
            Some(v) => match Url::parse(v){
                Ok(u) => u,
                Err(e) => {
                    return Err(e.into());
                }
            },
            None => {
                return Err("No URL supplied!".into());
            }
        };

        // Get verbosity level
        let verbose: bool = check_bool("verbose");
        let quiet: bool = check_bool("quiet");

        let verbosity: u32 = {
            if verbose {
                2
            }
            else if quiet {
                0
            }
            else {
                1
            }
        };

        // check for patch amsi, patch etw and sandbox detection option
        let patch_amsi: bool = check_bool("patch_amsi");
        let patch_etw: bool = check_bool("patch_etw");
        let detect_sandbox: bool = check_bool("detect_sandbox");

        // Get Decreytion Key
        let key: Option<String> = None;
        // Put them all in a struct
        Ok(LoaderOptions {
            url,
            verbosity,
            patch_amsi,
            patch_etw,
            detect_sandbox,
            key
        })
    }
}
