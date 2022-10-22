#![allow(dead_code)]
use crate::error::AppError;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Diagnostics::Debug::*;

pub struct PeHeaders {
    pub dos_hdr:    IMAGE_DOS_HEADER,
    pub nt_hdr:     IMAGE_NT_HEADERS64,
    pub section_hdr_arr: Vec<IMAGE_SECTION_HEADER>,
}

impl PeHeaders {
    pub fn new() -> PeHeaders {
        let pe_hdr = PeHeaders {
                dos_hdr: IMAGE_DOS_HEADER::default(),
                nt_hdr: IMAGE_NT_HEADERS64::default(),
                section_hdr_arr: Vec::new(),
            };
        pe_hdr
    }

    pub fn populate(&mut self, pe_buf: Vec<u8>) -> Result<(), AppError> {
        let max_nt_hdr_offset: usize = 1024; 
        let nt_hdr_offset: usize;
        let pe_dos_hdr: IMAGE_DOS_HEADER;
        let pe_nt_hdr: IMAGE_NT_HEADERS64;
        let pe_file_hdr: IMAGE_FILE_HEADER;
        let size_of_optional_hdr: usize;
        let number_of_sections: usize;
        let mut pe_section_hdr_arr: Vec<IMAGE_SECTION_HEADER> = Vec::new();

        // Check if PE buffer is empty
        if pe_buf.is_empty() {
            return Err(AppError{description: String::from("PE Buffer Empty")});
        }

        // Check if PE buffer reference is null
        if pe_buf.as_ptr().is_null(){
            return Err(AppError{description: String::from("PE Buffer Reference NULL")});
        }

        // Get DOS Header
        pe_dos_hdr = unsafe { std::ptr::read(pe_buf.as_ptr() as *const IMAGE_DOS_HEADER)};
        if pe_dos_hdr.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(AppError{description: String::from("Invalid DOS Signature")});
        }
        println!("[i] Extracted DOS Header");

        // Offset of NT Header
        nt_hdr_offset = usize::try_from(pe_dos_hdr.e_lfanew).unwrap_or(pe_dos_hdr.e_lfanew as usize);
        if nt_hdr_offset > max_nt_hdr_offset {
            return Err(AppError { description: String::from("NT Header Offset > 1024") });
        }

        // Get NT Header
        pe_nt_hdr = unsafe {
            let __nt_hdr_vec = &pe_buf[nt_hdr_offset..];
            std::ptr::read(__nt_hdr_vec.as_ptr() as *const IMAGE_NT_HEADERS64)
        };

        if pe_nt_hdr.Signature != IMAGE_NT_SIGNATURE {
            return Err(AppError { description: String::from("Invalid NT Signature") });
        }
        println!("[i] Extracted NT Header");

        // Get File Header Field
        pe_file_hdr = pe_nt_hdr.FileHeader;

        // Number of Sections = FileHeader->NumberOfSections
        number_of_sections = u32::try_from(pe_file_hdr.NumberOfSections).unwrap_or(pe_file_hdr.NumberOfSections as u32) as usize;
        println!("[i] Fetched PE has {} sections", number_of_sections);

        // Offset of Section Header Array is:
        // Offset of NT Header + sizeof(Signature(u32)) + sizeof(FileHeader) + FileHeader->SizeOfOptionalHeader
        size_of_optional_hdr = u32::try_from(pe_file_hdr.SizeOfOptionalHeader)
                                .unwrap_or(pe_file_hdr.SizeOfOptionalHeader as u32) as usize;
        let section_header_offset: usize = nt_hdr_offset 
                                        + std::mem::size_of::<u32>() 
                                        + std::mem::size_of::<IMAGE_FILE_HEADER>() 
                                        + size_of_optional_hdr;

        // Get Array of PE Headers
        let mut arr_part: &[u8] = &pe_buf[section_header_offset..];
        let mut i:usize = 0;
    
        while i < number_of_sections {
            let section_entry: IMAGE_SECTION_HEADER =  unsafe { std::ptr::read(arr_part.as_ptr() as *const IMAGE_SECTION_HEADER)};
            arr_part = &arr_part[std::mem::size_of::<IMAGE_SECTION_HEADER>()..];
            pe_section_hdr_arr.push(section_entry);
            //__print_section_header(&section_entry);
            i = i + 1;
        }

        self.dos_hdr = pe_dos_hdr;
        self.nt_hdr = pe_nt_hdr;
        self.section_hdr_arr = pe_section_hdr_arr.clone();
        Ok(())
    }

    // Print DOS Headers
    pub fn print_dos_header(&self) {
        let dos_hdr: IMAGE_DOS_HEADER = self.dos_hdr;
        println!("======================= DOS HEADER =======================");
        println!("[i] Magic Number\t\t\t{:#x}", dos_hdr.e_magic);
        println!("[i] Bytes on last page of file\t\t{:#x}", dos_hdr.e_cblp); 
        println!("[i] Pages in file\t\t\t{}", dos_hdr.e_cp); 
        println!("[i] Relocations\t\t\t\t{:#x}", dos_hdr.e_crlc); 
        println!("[i] Size of header in paragraphs\t{}", dos_hdr.e_cparhdr); 
        println!("[i] Minimum extra paragraphs needed\t{:#x}", dos_hdr.e_minalloc); 
        println!("[i] Maximum extra paragraphs needed\t{:#x}", dos_hdr.e_maxalloc); 
        println!("[i] Initial SS value\t\t\t{:#x}", dos_hdr.e_ss); 
        println!("[i] Initial SP value\t\t\t{:#x}",dos_hdr.e_sp); 
        println!("[i] Checksum\t\t\t\t{:#x}", dos_hdr.e_csum); 
        println!("[i] Initial IP value\t\t\t{:#x}", dos_hdr.e_ip); 
        println!("[i] Initial CS value\t\t\t{:#x}", dos_hdr.e_cs); 
        println!("[i] File address of relocation table\t{:#x}", dos_hdr.e_lfarlc); 
        println!("[i] Overlay number\t\t\t{}", dos_hdr.e_ovno);
        println!("[i] Reserved words\t\t\t{:?}", dos_hdr.e_res);
        println!("[i] OEM identifier\t\t\t{}", dos_hdr.e_oemid);
        println!("[i] OEM information\t\t\t{}", dos_hdr.e_oeminfo); 
        println!("[i] Reserved words\t\t\t{:?}", dos_hdr.e_res2); 
        println!("[i] File address of new exe header\t{:#x}", {let offset = dos_hdr.e_lfanew; offset}); 
        println!();
    }

    // Print NT Headers
    pub fn print_nt_header(&self) {
        let file_hdr: IMAGE_FILE_HEADER = self.nt_hdr.FileHeader;
        println!("======================= NT HEADERS =======================");
        println!("[i] Signature\t\t\t\t{}", self.nt_hdr.Signature);
        println!("[i] Machine Type\t\t\t{:#x}", file_hdr.Machine.0);
        println!("[i] Number of Sections\t\t\t{}", file_hdr.NumberOfSections);
        println!("[i] Time Date Stamp\t\t\t{:#x}", file_hdr.TimeDateStamp);
        println!("[i] Pointer to Symbol Table\t\t{:#x}", file_hdr.PointerToSymbolTable);
        println!("[i] Number of Symbols\t\t\t{}", file_hdr.NumberOfSymbols);
        println!("[i] Size of Optional Header\t\t{}",file_hdr.SizeOfOptionalHeader);
        println!("[i] Characteristics:\t\t\t{:#x}",file_hdr.Characteristics.0);
        self.print_optional_header();
    }

    // Print Optional Header
    pub fn print_optional_header(&self) {
        let opt_header = self.nt_hdr.OptionalHeader;
        let data_dir:[IMAGE_DATA_DIRECTORY; 16] = self.nt_hdr.OptionalHeader.DataDirectory;
        println!("==================== Optional HEADERS ====================");
        println!("[i] Magic Number\t\t\t{:#x}", opt_header.Magic.0);
        println!("[i] Major Linker Version\t\t{:#x}", opt_header.MajorLinkerVersion);
        println!("[i] Minor Linker Version\t\t{:#x}", opt_header.MinorLinkerVersion);
        println!("[i] Size of Code\t\t\t{:#x}", opt_header.SizeOfCode);
        println!("[i] Size of Initialized Data\t\t{:#x}", opt_header.SizeOfInitializedData);
        println!("[i] Size of Uninitialized Data\t\t{:#x}", opt_header.SizeOfUninitializedData);
        println!("[i] Address of Entry Point\t\t{:#x}", opt_header.AddressOfEntryPoint);
        println!("[i] Base of Code\t\t\t{:#x}", opt_header.BaseOfCode);
        println!("[i] Image Base\t\t\t\t{:#x}", {let img_base = opt_header.ImageBase; img_base});
        println!("[i] Section Alignment\t\t\t{:#x}",opt_header.SectionAlignment);
        println!("[i] File Alignment\t\t\t{:#x}", opt_header.FileAlignment);
        println!("[i] Major Operating System Version\t{:#x}", opt_header.MajorOperatingSystemVersion);
        println!("[i] Minor Operating System Version\t{:#x}", opt_header.MinorOperatingSystemVersion);
        println!("[i] Major Image Version\t\t\t{:#x}", opt_header.MajorImageVersion);
        println!("[i] Minor Image Version\t\t\t{:#x}", opt_header.MinorImageVersion);
        println!("[i] Major Subsystem Version\t\t{}", opt_header.MajorSubsystemVersion);
        println!("[i] Minor Subsystem Version\t\t{}", opt_header.MinorSubsystemVersion);
        println!("[i] Win32 Version\t\t\t{}", opt_header.Win32VersionValue);
        println!("[i] Size of Image\t\t\t{}", opt_header.SizeOfImage);
        println!("[i] Size of Headers\t\t\t{}", opt_header.SizeOfHeaders);
        println!("[i] Checksum\t\t\t\t{}", opt_header.CheckSum);
        println!("[i] Subsystem\t\t\t\t{}", opt_header.Subsystem.0);
        println!("[i] DLL Characteristics\t\t\t{:#x}", opt_header.DllCharacteristics.0);
        println!("[i] Size Of StackReserve\t\t{:#x}", {let s_stck_res = opt_header.SizeOfStackReserve; s_stck_res});
        println!("[i] Size Of Stack Commit\t\t{:#x}", {let s_stck_com = opt_header.SizeOfStackCommit; s_stck_com});
        println!("[i] Size Of Heap Reserve\t\t{:#x}", {let s_heap_res = opt_header.SizeOfHeapReserve; s_heap_res});
        println!("[i] Size Of HeapCommit\t\t\t{:#x}", {let s_heap_com = opt_header.SizeOfHeapCommit; s_heap_com});
        println!("[i] Loader Flags\t\t\t{}", opt_header.LoaderFlags);
        println!("[i] Number Of Rva And Sizes\t\t{}", opt_header.NumberOfRvaAndSizes);
        println!("[i] Data Directory Entries:");
        println!();
        for i in 0..16 {
            println!("[i] Entry\t\t{}", i);
            println!("[i] Virtual Address\t{:#x}",data_dir[i].VirtualAddress);
            println!("[i] Size\t\t{:#x}",data_dir[i].Size);
            println!();
        }
        println!();
    }

    pub fn print_headers(&self){
        println!("======================= PE HEADERS =======================");
        self.print_dos_header();
        self.print_nt_header();
        println!("==========================================================");
        println!();
    }
}