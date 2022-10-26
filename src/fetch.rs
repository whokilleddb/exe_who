use url::Url;
use std::io::Write;
use crate::error::AppError;
use std::convert::TryFrom;
use std::io::{Error, ErrorKind};
use reqwest::{self, header};


// Get URL as user input
pub fn fetch_url() -> Result<String, std::io::Error> {
    let mut url_str: String = String::new();
    print!("[>] Enter URL('quit' to exit): ");

    // Flush stdout
    match std::io::stdout().flush() {
        Ok(v) => v,
        Err(_e) => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,"[-] Failed to flush STDOUT!"));
        },
    };

    // Take input from command line
    match std::io::stdin().read_line(&mut url_str){
        Ok(v) => v,
        Err(_e) => {
            return Err(Error::new(ErrorKind::InvalidInput,"[-] Failed to readline!"));
        }, 
    };   

    // Return URL string
    Ok(url_str.clone())
}


// Fetch PE
pub async fn fetch_pe(url: Url) -> Result<Vec<u8>, AppError> {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,  
        header::HeaderValue::from_static("Mozilla/5.0....")
    );

    let client = match reqwest::Client::builder().default_headers(headers).build(){
                    Ok(val) => val,
                    Err(e) => {
                        eprintln!("[i] Error occured as: {:?}", e);
                        return Err(
                            AppError{description: String::from("Failed to create Request Builder :(")}
                        );
                    }
                };

    let resp = match client.get(url.as_str()).send().await {
        Ok(val) => val,
        Err(e) => {
            eprintln!("[i] Error occured as: {:?}", e);
            return Err(AppError{description: String::from("Failed to download PE :(")});
        }
    };


    let content_len = match resp.content_length() {
        Some(val) => val,
        None => {
            return Err(AppError{description: String::from("Fetched PE is empty :(")});
        }
    };

    let pe_bytes = match resp.bytes().await {
        Ok(val) => val,
        Err(e) => {
            eprintln!("[!] Error occured at\t{:?}", e);
            return Err(AppError{description: String::from("Failed to fetch PE bytes :(")});
        }
    };

    let pe_bytes: Vec<u8> = pe_bytes.as_ref().to_vec();
    println!("[i] PE Bytes fetched: {}", pe_bytes.len());

    Ok(pe_bytes)
                   
}