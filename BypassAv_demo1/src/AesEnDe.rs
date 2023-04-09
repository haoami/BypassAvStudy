

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand_core::{OsRng, RngCore};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const KEY: &[u8; 16] = b"abcdedghijklmnop"; // 模拟密钥，请勿在实际程序中使用
const iv : [u8;16]=[160, 59, 42, 145, 118, 130, 125, 90, 138, 69, 35, 30, 12, 157, 118, 160];

/// 生成随机 iv
pub fn generate_iv() -> [u8; 16] {
    let mut rng = OsRng;
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);

    bytes
}

/// 加密
pub fn encrypt(plain: &[u8]) -> (Vec<u8>, [u8; 16]) {

    let mut buf = [0u8; 48];
    let pt_len = plain.len();
    buf[..pt_len].copy_from_slice(plain);
    let ct = Aes128CbcEnc::new(KEY.into(), &iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(plain, &mut buf)
        .unwrap();

    (ct.to_vec(), iv)
}

/// 解密
pub fn decrypt(cipher: &[u8], iv_var: [u8; 16]) -> Vec<u8> {
    let cipher_len = cipher.len();
    let mut buf = [0u8;  0x10000 ];
    buf[..cipher_len].copy_from_slice(cipher);

    let pt = Aes128CbcDec::new(KEY.into(), &iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(cipher, &mut buf)
        .unwrap();

    pt.to_vec()
}



