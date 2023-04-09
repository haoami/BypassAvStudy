use std::str::FromStr;

use uuid::Uuid;


pub fn StrToU8Array(str : &str) -> Vec<u8> {
    let hex_string = str.replace("\\x", "");
    let bytes = hex::decode(hex_string).unwrap();
    let result = bytes.as_slice();
    // println!("{:?}", result);
    result.to_vec()
}
fn u8ToStringOrHex( barry: &[u8] , choice : u8) {

    use std::fmt::Write;
    let mut signature_string = String::new();
    match choice {
        1=>{
            for a in barry.iter() { 
                write!(signature_string, "{:02x}", a);

            }
            println!("the entire u8Array as a single HexString: {}", signature_string);
        },
        2=>{
            signature_string = String::from_utf8(barry.to_vec()).unwrap();
            println!("the entire u8Array as a single string: {}", signature_string);
        }
        _=>{}
    }

}

pub fn WriteUuidStringToMemory(uuid_string: &str, memory_ptr :*mut u8)  -> i32{
    let uuid_string = uuid_string;
    let uuid = Uuid::from_str(uuid_string).unwrap();
    let mut uuid_bytes = uuid.into_bytes();
    uuid_bytes[0..4].reverse();
    uuid_bytes[4..6].reverse();
    uuid_bytes[6..8].reverse();
    for i in 0..16 {
        unsafe {
            *(memory_ptr.add(i)) = uuid_bytes[i] ;
        }
    }

    return 0;
}
pub fn print_memory(memory_ptr: *const u8, size: usize) {
    unsafe {
        let memory_slice = std::slice::from_raw_parts(memory_ptr, size);
        for byte in memory_slice {
            print!("{:02x} ", byte);
        }
    }
    println!("");
}