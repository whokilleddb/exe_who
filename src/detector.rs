use walkdir::WalkDir;
use colored::Colorize;
use std::collections::HashMap;

pub fn detect_edrs()->bool {
    let mut b_edr = false;
    let mut edrs = HashMap::new();
    edrs.insert("atrsdfw.sys","Altiris Symantec");
    edrs.insert("avgtpx86.sys","AVG Technologies");
    edrs.insert("avgtpx64.sys","AVG Technologies");
    edrs.insert("naswSP.sys","Avast");
    edrs.insert("edrsensor.sys","BitDefender SRL");
    edrs.insert("CarbonBlackK.sys","Carbon Black");
    edrs.insert("parity.sys","Carbon Black");
    edrs.insert("cbk7.sys","Carbon Black");
    edrs.insert("cbstream","Cargon Black");
    edrs.insert("csacentr.sys","Cisco");
    edrs.insert("csaenh.sys","Cisco");
    edrs.insert("csareg.sys","Cisco");
    edrs.insert("csascr.sys","Cisco");
    edrs.insert("csaav.sys","Cisco");
    edrs.insert("csaam.sys","Cisco");
    edrs.insert("rvsavd.sys","CJSC Returnil Software");
    edrs.insert("cfrmd.sys","Comodo Security");
    edrs.insert("cmdccav.sys","Comodo Security");
    edrs.insert("cmdguard.sys","Comodo Security");
    edrs.insert("CmdMnEfs.sys","Comodo Security");
    edrs.insert("MyDLPMF.sys","Comodo Security");
    edrs.insert("im.sys","CrowdStrike");
    edrs.insert("csagent.sys","CrowdStrike");
    edrs.insert("CybKernelTracker.sys","CyberArk Software");
    edrs.insert("CRExecPrev.sys","Cybereason");
    edrs.insert("CyOptics.sys","Cylance Inc.");
    edrs.insert("CyProtectDrv32.sys","Cylance Inc.");
    edrs.insert("CyProtectDrv64.sys","Cylance Inc.");
    edrs.insert("groundling32.sys","Dell Secureworks");
    edrs.insert("groundling64.sys","Dell Secureworks");
    edrs.insert("esensor.sys","Endgame");
    edrs.insert("edevmon.sys","ESET");
    edrs.insert("ehdrv.sys","ESET");
    edrs.insert("FeKern.sys","FireEye");
    edrs.insert("WFP_MRT.sys","FireEye");
    edrs.insert("xfsgk.sys","F-Secure");
    edrs.insert("fsatp.sys","F-Secure");
    edrs.insert("fshs.sys","F-Secure");
    edrs.insert("HexisFSMonitor.sys","Hexis Cyber Solutions");
    edrs.insert("klifks.sys","Kaspersky");
    edrs.insert("klifaa.sys","Kaspersky");
    edrs.insert("Klifsm.sys","Kaspersky");
    edrs.insert("mbamwatchdog.sys","Malwarebytes");
    edrs.insert("mfeaskm.sys","McAfee");
    edrs.insert("mfencfilter.sys","McAfee");
    edrs.insert("PSINPROC.SYS","Panda Security");
    edrs.insert("PSINFILE.SYS","Panda Security");
    edrs.insert("amfsm.sys","Panda Security");
    edrs.insert("amm8660.sys","Panda Security");
    edrs.insert("amm6460.sys","Panda Security");
    edrs.insert("eaw.sys","Raytheon Cyber Solutions");
    edrs.insert("SAFE-Agent.sys","SAFE-Cyberdefense");
    edrs.insert("SentinelMonitor.sys","SentinelOne");
    edrs.insert("SAVOnAccess.sys","Sophos");
    edrs.insert("savonaccess.sys","Sophos");
    edrs.insert("sld.sys","Sophos");
    edrs.insert("pgpwdefs.sys","Symantec");
    edrs.insert("GEProtection.sys","Symantec");
    edrs.insert("diflt.sys","Symantec");
    edrs.insert("sysMon.sys","Symantec");
    edrs.insert("ssrfsf.sys","Symantec");
    edrs.insert("emxdrv2.sys","Symantec");
    edrs.insert("reghook.sys","Symantec");
    edrs.insert("spbbcdrv.sys","Symantec");
    edrs.insert("bhdrvx86.sys","Symantec");
    edrs.insert("bhdrvx64.sys","Symantec");
    edrs.insert("SISIPSFileFilter.sys","Symantec");
    edrs.insert("symevent.sys","Symantec");
    edrs.insert("vxfsrep.sys","Symantec");
    edrs.insert("VirtFile.sys","Symantec");
    edrs.insert("SymAFR.sys","Symantec");
    edrs.insert("symefasi.sys","Symantec");
    edrs.insert("symefa.sys","Symantec");
    edrs.insert("symefa64.sys","Symantec");
    edrs.insert("SymHsm.sys","Symantec");
    edrs.insert("evmf.sys","Symantec");
    edrs.insert("GEFCMP.sys","Symantec");
    edrs.insert("VFSEnc.sys","Symantec");
    edrs.insert("pgpfs.sys","Symantec");
    edrs.insert("fencry.sys","Symantec");
    edrs.insert("symrg.sys","Symantec");
    edrs.insert("ndgdmk.sys","Verdasys Inc");
    edrs.insert("ssfmonm.sys","Webroot Software");
    edrs.insert("dlpwpdfltr.sys","Trend Micro Software");

    for entry in WalkDir::new("C:\\Windows\\System32\\drivers\\") 
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok()) {
        let f_name = entry.file_name().to_string_lossy();
        if  edrs.contains_key(f_name.as_ref()) {
            b_edr = true;
            eprintln!("[!] Detected EDR: {}\r\n", edrs.get(f_name.as_ref()).unwrap().red());
        } else if f_name.starts_with("EcatService") {
            b_edr = true;
            eprintln!("[!] Detected EDR: {}", "RSA NetWitness Endpoint\r\n".red());
        }
    }

    b_edr
}