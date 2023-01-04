use std::option::Option;
use sysinfo::{System, SystemExt};

pub fn is_sandbox()-> bool {
    let has_sus_str = |name: Option<String>|{
        match name {
            Some(v) => {
                let name_lower_case = v.to_ascii_lowercase();
                if name_lower_case.contains("virtual") || name_lower_case.contains("vmware") {
                    return true;
                }
                return false;
            }
            None => {
                return false;
            }
        }
    };

    let mut sandbox = false;
    println!("[+] Performing T1497.001 System Checks");

    // Please note that we use "new_all" to ensure that all list of
    // components, network interfaces, disks and users are already
    // filled!
    let mut sys = System::new_all();

    // First we update all information of our `System` struct.
    sys.refresh_all();
    
    // Enumerating all Network interfaces
    println!("[i] Enumerating all network interfaces");
    for (interface_name, _data) in sys.networks() {
        if has_sus_str(Some(interface_name.clone())) {
            println!("[!] Found Interface\t\t{}", interface_name);
            sandbox = true;
        }
    }

    // Check system name
    if has_sus_str(sys.name()) {
        println!("[!] System Name\t\t{}", sys.name().unwrap());
        sandbox = true;
    }

    // Check Hostname
    if has_sus_str(sys.host_name()) {
        println!("[!] System Name\t\t{}", sys.host_name().unwrap());
        sandbox = true;
    }

    return sandbox;
}

