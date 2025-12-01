#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use winapi::um::winnt::LIST_ENTRY;
use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{HANDLE, UNICODE_STRING};


pub type PVOID = *mut c_void;
pub type PWCHAR = *mut u16;
pub type ULONG = u32;
pub type ULONG_PTR = usize;

pub const RTL_MAX_DRIVE_LETTERS: usize = 32;

#[repr(C)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: HANDLE,
}

#[repr(C)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    pub Flags: u16,
    pub Length: u16,
    pub TimeStamp: u32,
    pub DosPath: UNICODE_STRING,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: ULONG,
    pub Length: ULONG,

    pub Flags: ULONG,
    pub DebugFlags: ULONG,

    pub ConsoleHandle: HANDLE,
    pub ConsoleFlags: ULONG,
    pub StandardInput: HANDLE,
    pub StandardOutput: HANDLE,
    pub StandardError: HANDLE,

    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: PWCHAR,

    pub StartingX: ULONG,
    pub StartingY: ULONG,
    pub CountX: ULONG,
    pub CountY: ULONG,
    pub CountCharsX: ULONG,
    pub CountCharsY: ULONG,
    pub FillAttribute: ULONG,

    pub WindowFlags: ULONG,
    pub ShowWindowFlags: ULONG,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
    pub CurrentDirectories: [RTL_DRIVE_LETTER_CURDIR; RTL_MAX_DRIVE_LETTERS],

    pub EnvironmentSize: ULONG_PTR,
    pub EnvironmentVersion: ULONG_PTR,
    pub PackageDependencyData: PVOID,
    pub ProcessGroupId: ULONG,
    pub LoaderThreads: ULONG,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union LARGE_INTEGER {
    pub QuadPart: i64,
    pub u: LargeIntegerStruct,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LargeIntegerStruct {
    pub LowPart: u32,
    pub HighPart: i32,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u32,
    pub SsHandle: *mut c_void,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY
}

#[repr(C)]
pub struct PEB {
    pub InheritedAddressSpace: BOOL,
    pub ReadImageFileExecOptions: BOOL,
    pub BeingDebugged: BOOL,
    pub Spare: BOOL,
    pub Mutant: HANDLE,
    pub ImageBase: *mut c_void,
    pub LoaderData: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub SubSystemData: *mut c_void,
    pub ProcessHeap: *mut c_void,
    pub FastPebLock: *mut c_void,
    pub FastPebUnlockRoutine: *mut c_void,
    pub EnvironmentUpdateCount: u32,
    pub KernelCallbackTable: *mut *mut c_void,
    pub EventLogSection: *mut c_void,
    pub EventLog: *mut c_void,
    pub Freelist: *mut c_void,
    pub TlsExpansionCounter: u32,
    pub TlsBitmap: *mut c_void,
    pub TlsBitmapBits: [u32; 2],
    pub ReadOnlySharedMemoryBase: *mut c_void,
    pub ReadOnlySharedMemoryHeap: *mut c_void,
    pub ReadOnlyStaticServerData: *mut *mut c_void,
    pub AnsiCodePageData: *mut c_void,
    pub OemCodePageData: *mut c_void,
    pub UnicodeCaseTableData: *mut c_void,
    pub NumberOfProcessors: u32,
    pub NtGlobalFlag: u32,
    pub Spare2: [u8; 4],
    pub CriticalSectionTimeout: LARGE_INTEGER,
    pub HeapSegmentReserve: u32,
    pub HeapSegmentCommit: u32,
    pub HeapDeCommitTotalFreeThreshold: u32,
    pub HeapDeCommitFreeBlockThreshold: u32,
    pub NumberOfHeaps: u32,
    pub MaximumNumberOfHeaps: u32,
    pub ProcessHeaps: *mut *mut *mut c_void,
    pub GdiSharedHandleTable: *mut c_void,
    pub ProcessStarterHelper: *mut c_void,
    pub GdiDCAttributeList: *mut c_void,
    pub LoaderLock: *mut c_void,
    pub OSMajorVersion: u32,
    pub OSMinorVersion: u32,
    pub OSBuildNumber: u32,
    pub OSPlatformId: u32,
    pub ImageSubSystem: u32,
    pub ImageSubSystemMajorVersion: u32,
    pub ImageSubSystemMinorVersion: u32,
    pub GdiHandleBuffer: [u32; 22],
    pub PostProcessInitRoutine: u32,
    pub TlsExpansionBitmap: u32,
    pub TlsExpansionBitmapBits: [u8; 80],
    pub SessionId: u32
}