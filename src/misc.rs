/// This file contains a bunch of useful Miscellaneous functions
use regex::*;
use std::env;
use lazy_static::lazy_static;

pub fn expand_env_vars(s:&str) -> std::io::Result<String>  {
    // See: https://play.rust-lang.org/?version=stable&mode=debug&edition=2018&gist=5ff99012f89d49907318a0d7f7a49b11
    lazy_static! {
        static ref ENV_VAR: Regex = Regex::new("%([[:word:]]*)%").expect("[!] Invalid Regex!");
    }

    let result: String = ENV_VAR.replace_all(s, |c:&Captures| match &c[1] {
        "" => String::from("%"),
        varname => env::var(varname).expect("Bad Var Name")
    }).into();

    Ok(result)
}
