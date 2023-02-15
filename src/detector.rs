use colored::Colorize;
use enigo::Enigo;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::time::Instant;
use walkdir::WalkDir;

pub fn detect_edrs() -> bool {
    let mut b_edr = false;
    let mut edrs = HashMap::new();
    edrs.insert("atrsdfw.sys", "Altiris Symantec");
    edrs.insert("avgtpx86.sys", "AVG Technologies");
    edrs.insert("avgtpx64.sys", "AVG Technologies");
    edrs.insert("naswSP.sys", "Avast");
    edrs.insert("edrsensor.sys", "BitDefender SRL");
    edrs.insert("CarbonBlackK.sys", "Carbon Black");
    edrs.insert("parity.sys", "Carbon Black");
    edrs.insert("cbk7.sys", "Carbon Black");
    edrs.insert("cbstream", "Cargon Black");
    edrs.insert("csacentr.sys", "Cisco");
    edrs.insert("csaenh.sys", "Cisco");
    edrs.insert("csareg.sys", "Cisco");
    edrs.insert("csascr.sys", "Cisco");
    edrs.insert("csaav.sys", "Cisco");
    edrs.insert("csaam.sys", "Cisco");
    edrs.insert("rvsavd.sys", "CJSC Returnil Software");
    edrs.insert("cfrmd.sys", "Comodo Security");
    edrs.insert("cmdccav.sys", "Comodo Security");
    edrs.insert("cmdguard.sys", "Comodo Security");
    edrs.insert("CmdMnEfs.sys", "Comodo Security");
    edrs.insert("MyDLPMF.sys", "Comodo Security");
    edrs.insert("im.sys", "CrowdStrike");
    edrs.insert("csagent.sys", "CrowdStrike");
    edrs.insert("CybKernelTracker.sys", "CyberArk Software");
    edrs.insert("CRExecPrev.sys", "Cybereason");
    edrs.insert("CyOptics.sys", "Cylance Inc.");
    edrs.insert("CyProtectDrv32.sys", "Cylance Inc.");
    edrs.insert("CyProtectDrv64.sys", "Cylance Inc.");
    edrs.insert("groundling32.sys", "Dell Secureworks");
    edrs.insert("groundling64.sys", "Dell Secureworks");
    edrs.insert("esensor.sys", "Endgame");
    edrs.insert("edevmon.sys", "ESET");
    edrs.insert("ehdrv.sys", "ESET");
    edrs.insert("FeKern.sys", "FireEye");
    edrs.insert("WFP_MRT.sys", "FireEye");
    edrs.insert("xfsgk.sys", "F-Secure");
    edrs.insert("fsatp.sys", "F-Secure");
    edrs.insert("fshs.sys", "F-Secure");
    edrs.insert("HexisFSMonitor.sys", "Hexis Cyber Solutions");
    edrs.insert("klifks.sys", "Kaspersky");
    edrs.insert("klifaa.sys", "Kaspersky");
    edrs.insert("Klifsm.sys", "Kaspersky");
    edrs.insert("mbamwatchdog.sys", "Malwarebytes");
    edrs.insert("mfeaskm.sys", "McAfee");
    edrs.insert("mfencfilter.sys", "McAfee");
    edrs.insert("PSINPROC.SYS", "Panda Security");
    edrs.insert("PSINFILE.SYS", "Panda Security");
    edrs.insert("amfsm.sys", "Panda Security");
    edrs.insert("amm8660.sys", "Panda Security");
    edrs.insert("amm6460.sys", "Panda Security");
    edrs.insert("eaw.sys", "Raytheon Cyber Solutions");
    edrs.insert("SAFE-Agent.sys", "SAFE-Cyberdefense");
    edrs.insert("SentinelMonitor.sys", "SentinelOne");
    edrs.insert("SAVOnAccess.sys", "Sophos");
    edrs.insert("savonaccess.sys", "Sophos");
    edrs.insert("sld.sys", "Sophos");
    edrs.insert("pgpwdefs.sys", "Symantec");
    edrs.insert("GEProtection.sys", "Symantec");
    edrs.insert("diflt.sys", "Symantec");
    edrs.insert("sysMon.sys", "Symantec");
    edrs.insert("ssrfsf.sys", "Symantec");
    edrs.insert("emxdrv2.sys", "Symantec");
    edrs.insert("reghook.sys", "Symantec");
    edrs.insert("spbbcdrv.sys", "Symantec");
    edrs.insert("bhdrvx86.sys", "Symantec");
    edrs.insert("bhdrvx64.sys", "Symantec");
    edrs.insert("SISIPSFileFilter.sys", "Symantec");
    edrs.insert("symevent.sys", "Symantec");
    edrs.insert("vxfsrep.sys", "Symantec");
    edrs.insert("VirtFile.sys", "Symantec");
    edrs.insert("SymAFR.sys", "Symantec");
    edrs.insert("symefasi.sys", "Symantec");
    edrs.insert("symefa.sys", "Symantec");
    edrs.insert("symefa64.sys", "Symantec");
    edrs.insert("SymHsm.sys", "Symantec");
    edrs.insert("evmf.sys", "Symantec");
    edrs.insert("GEFCMP.sys", "Symantec");
    edrs.insert("VFSEnc.sys", "Symantec");
    edrs.insert("pgpfs.sys", "Symantec");
    edrs.insert("fencry.sys", "Symantec");
    edrs.insert("symrg.sys", "Symantec");
    edrs.insert("ndgdmk.sys", "Verdasys Inc");
    edrs.insert("ssfmonm.sys", "Webroot Software");
    edrs.insert("dlpwpdfltr.sys", "Trend Micro Software");

    for entry in WalkDir::new("C:\\Windows\\System32\\drivers\\")
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let f_name = entry.file_name().to_string_lossy();
        if edrs.contains_key(f_name.as_ref()) {
            b_edr = true;
            eprintln!(
                "[!] Detected EDR: {}\r\n",
                edrs.get(f_name.as_ref()).unwrap().red()
            );
        } else if f_name.starts_with("EcatService") {
            b_edr = true;
            eprintln!("[!] Detected EDR: {}", "RSA NetWitness Endpoint\r\n".red());
        }
    }

    b_edr
}

// Check for mouse pointer activity and sleep patching
fn mouse_activity_sleep_patch() -> bool {
    // Check initial location
    let initial_cursor_location: (i32, i32) = Enigo::mouse_location();
    let ix = initial_cursor_location.0;
    let iy = initial_cursor_location.1;

    // Set sleep duration
    let duration = std::time::Duration::new(10, 0);

    // Sleep for 10s
    let start = Instant::now();
    std::thread::sleep(duration);
    let elapsed = start.elapsed();

    // Check cursor final location
    let final_cursor_location: (i32, i32) = Enigo::mouse_location();
    let fx = final_cursor_location.0;
    let fy = final_cursor_location.1;

    if ix == fx || iy == fy || (fy - iy) == (fx - ix) {
        return false;
    }

    let lower_limit = 9050_u128;
    let upper_limit = 10050_u128;
    let delta: u128 = elapsed.as_millis();
    if delta < lower_limit || delta > upper_limit {
        return false;
    }

    true
}

// Check for Common files found in Sandboxes
fn check_sandbox_files() -> bool {
    let sus_files: [&'static str; 32] = [
        "C:\\Windows\\System32\\drivers\\Vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vm3dgl.dll",
        "C:\\Windows\\System32\\drivers\\vmdum.dll",
        "C:\\Windows\\System32\\drivers\\vm3dver.dll",
        "C:\\Windows\\System32\\drivers\\vmtray.dll",
        "C:\\Windows\\System32\\drivers\\vmci.sys",
        "C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmx_svga.sys",
        "C:\\Windows\\System32\\drivers\\vmxnet.sys",
        "C:\\Windows\\System32\\drivers\\VMToolsHook.dll",
        "C:\\Windows\\System32\\drivers\\vmhgfs.dll",
        "C:\\Windows\\System32\\drivers\\vmmousever.dll",
        "C:\\Windows\\System32\\drivers\\vmGuestLib.dll",
        "C:\\Windows\\System32\\drivers\\VmGuestLibJava.dll",
        "C:\\Windows\\System32\\drivers\\vmscsi.sys",
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
        "C:\\Windows\\System32\\vboxdisp.dll",
        "C:\\Windows\\System32\\vboxhook.dll",
        "C:\\Windows\\System32\\vboxmrxnp.dll",
        "C:\\Windows\\System32\\vboxogl.dll",
        "C:\\Windows\\System32\\vboxoglarrayspu.dll",
        "C:\\Windows\\System32\\vboxoglcrutil.dll",
        "C:\\Windows\\System32\\vboxoglerrorspu.dll",
        "C:\\Windows\\System32\\vboxoglfeedbackspu.dll",
        "C:\\Windows\\System32\\vboxoglpackspu.dll",
        "C:\\Windows\\System32\\vboxoglpassthroughspu.dll",
        "C:\\Windows\\System32\\vboxservice.exe",
        "C:\\Windows\\System32\\vboxtray.exe",
        "C:\\Windows\\System32\\VBoxControl.exe",
    ];

    let mut count = 0;
    for path in sus_files.iter() {
        if Path::new(path).exists() {
            println!("[!] Found {}", path.on_red());
            count += 1;
        }
    }

    if count == 0 {
        return true;
    }
    false
}

// Check if Filename is the hash of the file
fn check_filename_hash() -> bool {
    let mut md5 = Md5::new();
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut buffer = Vec::new();

    let path = match env::current_exe() {
        Ok(_val) => _val,
        Err(_e) => {
            return false;
        }
    };

    let mut f = match File::open(&path) {
        Ok(_val) => _val,
        Err(_e) => {
            return false;
        }
    };

    match f.read_to_end(&mut buffer) {
        Ok(_val) => _val,
        Err(_e) => {
            return false;
        }
    };

    md5.update(&buffer);
    sha256.update(&buffer);
    sha1.update(&buffer);

    let md5 = md5.finalize();
    let sha256 = sha256.finalize();
    let sha1 = sha1.finalize();
    let md5_hash = String::from_utf8_lossy(&md5);
    let sha256_hash = String::from_utf8_lossy(&sha256);
    let sha1_hash = String::from_utf8_lossy(&sha1);

    let file_name = path
        .file_stem()
        .expect("Failed to extract file name")
        .to_string_lossy();

    !(md5_hash[..] == file_name || sha256_hash[..] == file_name || sha1_hash[..] == file_name)
}

pub fn check_sandbox() -> bool {
    println!(
        "[i] Checking {} & {}",
        "Cursor Activity".cyan(),
        "Sleep Patching".magenta()
    );
    let mut flag = mouse_activity_sleep_patch();

    println!("[i] Checking for {}", "Sandbox Files".red());
    flag &= check_sandbox_files();

    println!("[i] Checking for {}", "Filename Hash".yellow());
    flag &= check_filename_hash();

    if !flag {
        eprintln!("[!] {}", "Sandbox Environment Suspected".red());
    }

    flag
}
