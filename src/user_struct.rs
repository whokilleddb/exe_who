#![allow(dead_code)]
use url::Url;
use std::fmt;
use clap::ArgMatches;

/// Struct to store options 
#[derive(Clone)]
pub struct LoaderOptions {
    url: Url,
    verbosity: i32, 
}

/// Dictate how the contents of the struct will be printed
impl fmt::Display for LoaderOptions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut msg = format!("[i] URL:\t\t\t{}\r\n", self.url);
        write!(f,"{}",msg)
    }
}

/// Implement various traits for LoaderOptions
impl LoaderOptions {
    /// Return new LoaderOptions struct
    pub fn new(&self, cmds: ArgMatches) {
        let url = cmds.get_one::<String>("url");
        println!("{:?}", url);
    } 
}