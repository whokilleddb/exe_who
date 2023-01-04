use std::option::Option;
use std::collections::HashMap;
use sysinfo::{System, SystemExt};

// https://github.com/LordNoteworthy/al-khaser/issues/189
const IDENTIFIER_STRINGS: &'static [&str] = &["virtual", "vmware", "vboxuser", "ieuser", 
                                                "currentuser", "sandbox", "user", "win7-traps", 
                                                "testuser", "maltest", "malware", "fortinet", 
                                                "flarevm", "johndoe"];

pub fn is_sandbox()-> bool {
    let sandbox;
    sandbox = t1497_001();
    return sandbox;
}

fn t1497_001()->bool{
    println!("[+] Performing T1497.001 System Checks");

    let mut userinfo: HashMap<&str, Option<String>> = HashMap::new();

    // Check for suspicious strings
    let has_sus_str = |name: Option<String>|{
        match name {
            Some(v) => {
                let name_lower_case = v.to_ascii_lowercase()
                                                .replace(&[
                                                    '(', ')', ',','-', '\"', '.', ';', ':', '\''
                                                    ][..], "");
                for identifier in IDENTIFIER_STRINGS {
                    if name_lower_case.contains(identifier) {
                        return true;
                    }
                }
                return false;
            }
            None => {
                return false;
            }
        }
    };

    // Check username for common names used by sandboxes
    // Used by: Astaroth
    userinfo.insert("Realname", Some(whoami::realname()));
    userinfo.insert("Devicename", Some(whoami::devicename()));
    userinfo.insert("Hostname", Some(whoami::hostname()));
    userinfo.insert("Username", Some(whoami::username()));

    for (k, v) in userinfo.iter(){
        if has_sus_str(v.clone()) {
            println!("[i] {} contains a suspicious string!", k);
            return true;
        }
        println!("[i] {}\t\t\t\t{}", k, v.as_ref().unwrap());
    }


    // Get system information
    let mut sys = System::new_all();
    sys.refresh_all();
    
    // Enumerating all Network interfaces
    println!("[i] Enumerating all network interfaces");
    for (interface_name, _data) in sys.networks() {
        if has_sus_str(Some(interface_name.clone())) {
            println!("[!] Found Interface\t\t{}", interface_name);
            return true;
        }
    }

    // Check system name
    println!("[i] Enumerating System Name");
    if has_sus_str(sys.name()) {
        println!("[!] Suspicious System Name\t\t{}", sys.name().unwrap());
        return true;
    }

    // Check Hostname
    println!("[i] Enumerating Host Name");
    if has_sus_str(sys.host_name()) {
        println!("[!] Suspicious Host Name\t\t{}", sys.host_name().unwrap());
        return true;
    }
    return false;
}
