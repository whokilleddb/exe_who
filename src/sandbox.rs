// use std::option::Option;
// use std::collections::HashMap;
// use sysinfo::{System, SystemExt};

//#[link(name = ".\\out\\exe_who", kind = "static")]

// extern {
//     fn check_virtualization()->i32;
// }

// https://github.com/a0rtega/pafish/

// https://github.com/LordNoteworthy/al-khaser/issues/189
const _IDENTIFIER_STRINGS: &'static [&str] = &["virtual", "vmware", "vboxuser", "ieuser", 
                                                "currentuser", "sandbox", "user", "win7-traps", 
                                                "testuser", "maltest", "malware", "fortinet", 
                                                "flarevm", "johndoe"];


fn t1497_001()->bool{
    println!("[+] Performing T1497.001 System Checks");

    // let mut userinfo: HashMap<&str, Option<String>> = HashMap::new();

    // // Check for suspicious strings
    // let has_sus_str = |name: Option<String>|{
    //     match name {
    //         Some(v) => {
    //             let name_lower_case = v.to_ascii_lowercase()
    //                                             .replace(&[
    //                                                 '(', ')', ',','-', '\"', '.', ';', ':', '\''
    //                                                 ][..], "");
    //             for identifier in IDENTIFIER_STRINGS {
    //                 if name_lower_case.contains(identifier) {
    //                     return true;
    //                 }
    //             }
    //             return false;
    //         }
    //         None => {
    //             return false;
    //         }
    //     }
    // };

    // // Check username for common names used by sandboxes
    // // Used by: Astaroth
    // userinfo.insert("Realname", Some(whoami::realname()));
    // userinfo.insert("Devicename", Some(whoami::devicename()));
    // userinfo.insert("Hostname", Some(whoami::hostname()));
    // userinfo.insert("Username", Some(whoami::username()));

    // // Check for strings
    // for (k, v) in userinfo.iter(){
    //     if has_sus_str(v.clone()) {
    //         println!("[i] {} contains a suspicious string!", k);
    //         return true;
    //     }
    //     println!("[i] {}\t\t\t\t{}", k, v.as_ref().unwrap());
    // }


    // // Get system information
    // let mut sys = System::new_all();
    // sys.refresh_all();
    
    // // Enumerating all Network interfaces
    // println!("[i] Enumerating all network interfaces");
    // for (interface_name, _data) in sys.networks() {
    //     if has_sus_str(Some(interface_name.clone())) {
    //         println!("[!] Found Interface\t\t{}", interface_name);
    //         return true;
    //     }
    // }

    // // Check system name
    // println!("[i] Enumerating System Name");
    // if has_sus_str(sys.name()) {
    //     println!("[!] Suspicious System Name\t\t{}", sys.name().unwrap());
    //     return true;
    // }

    // // Check Hostname
    // println!("[i] Enumerating Host Name");
    // if has_sus_str(sys.host_name()) {
    //     println!("[!] Suspicious Host Name\t\t{}", sys.host_name().unwrap());
    //     return true;
    // }
    return false;
}


fn t1497_002() -> bool {
    println!("[+] Performing T1497.002 User Activity Based Checks");
    return false;
}

fn t1497_003() -> bool {
    println!("[+] Performing T1497.002 Time Based Evasion");
    return false;
}

pub fn is_sandbox() -> bool {
    println!("[i] Checking for sandbox");
    let sys_check = t1497_001();
    let user_behav_checks = t1497_002();
    let time_checks = t1497_003();
    
    return sys_check && user_behav_checks && time_checks;
}