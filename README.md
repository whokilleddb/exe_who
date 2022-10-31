# Executables on Disk? _Preposterous!_

Saving executables to disk is like telling EDRs that _"Hey! Take a look at this thing I just fetched from the Internet!"_. No Red-Teamer wants that at the end of the day. That's why we are here to help!

# Compile and Build!
Compiling is as easy as:
```bash
C:\Users\User\Codes\exe_who> cargo build --release
```
# Current Features
- Patch ETW
- Sandbox Detection
  - User Activity Detection
  - Check for Sandbox Drivers
  - Check for Sleep Patching
  - Check Filename Hash
- Check for EDR drivers
- Fetch PEs and DLLs and run them in-memory
