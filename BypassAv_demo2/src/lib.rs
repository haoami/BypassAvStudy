use std::os::windows::raw::HANDLE;
use ntapi::ntpsapi::{ PS_ATTRIBUTE_LIST};
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::ntdef::{NTSTATUS,  OBJECT_ATTRIBUTES, VOID, PVOID};
use winapi::shared::minwindef::{ULONG, LPVOID};
use winapi::um::winnt::ACCESS_MASK;

#[link(name = "sys")]
extern "C" {
    pub fn NtCreateThreadEx(
        ThreadHandle: *mut HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ProcessHandle: HANDLE,
        StartRoutine: *mut VOID,
        Argument: *mut VOID,
        CreateFlags: ULONG,
        ZeroBits: SIZE_T,
        StackSize: SIZE_T,
        MaximumStackSize: SIZE_T,
        AttributeList: *mut PS_ATTRIBUTE_LIST
    ) -> NTSTATUS;
}

#[link(name = "sys")]
extern "C"{
    pub fn NtTestAlert() ->NTSTATUS;
}

#[link(name = "sys")]
extern "C"{
    pub fn NtAllocateVirtualMemory(
        ProcessHandle : HANDLE,
        BaseAddress : *mut PVOID,
        ZeroBits : ULONG,
        RegionSize : *mut SIZE_T,
        AllocationType : ULONG,
        Protect : ULONG
    ) ->NTSTATUS;
}



#[link(name = "sys")]
extern "C" {
    pub fn NtWriteVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: LPVOID,
        Buffer: LPVOID,
        NumberOfBytesToWrite: SIZE_T,
        NumberOfBytesWritten: *mut SIZE_T,
    ) -> NTSTATUS;
}