use anyhow::anyhow;
use chacha20poly1305::{
    aead::{NewAead, AeadInPlace},
    XChaCha20Poly1305,
};
use std::{
    fs::{self},
//     io::{Read, Write},
};

pub fn encrypt_small_file(
    data: &str,
    filepath: &str,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<(), anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut buffer: Vec<u8> = Vec::with_capacity(256);
    buffer.extend_from_slice(data.as_bytes());
//     buffer.extend([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

//     let mut ciphertext = cipher
//             .encrypt(nonce.into(), data.as_ref())
//             .map_err(|err| anyhow!("Encrypting file: {}", err))?;
    for _r in 1..=3 {
        cipher
            .encrypt_in_place(nonce.into(), b"", &mut buffer)
            .map_err(|err| anyhow!("Encrypting file: {}", err))?;
    }

    println!("buffer len {}", buffer.len());
    fs::write(&filepath, buffer)?;

    Ok(())
}

pub fn decrypt_small_file(
    encrypted_file_path: &str,
//     dist: &str,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<String, anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let file_data = fs::read(encrypted_file_path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(256);
    buffer.extend(file_data);
//     buffer.extend([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    for _r in 1..=3 {
        cipher
            .decrypt_in_place(nonce.into(), b"", &mut buffer)
            .map_err(|err| anyhow!("Decrypting file: {}", err))?;
    }
    println!("{}", buffer.len());

//     fs::write(&dist, decrypted_file)?;

    Ok(String::from_utf8(buffer)?)
}

// fn encrypt_large_file(
//     source_file_path: &str,
//     dist_file_path: &str,
//     key: &[u8; 32],
//     nonce: &[u8; 19],
// ) -> Result<(), anyhow::Error> {
//     let aead = XChaCha20Poly1305::new(key.as_ref().into());
//     let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
//
//     const BUFFER_LEN: usize = 500;
//     let mut buffer = [0u8; BUFFER_LEN];
//
//     let mut source_file = File::open(source_file_path)?;
//     let mut dist_file = File::create(dist_file_path)?;
//
//     loop {
//         let read_count = source_file.read(&mut buffer)?;
//
//         if read_count == BUFFER_LEN {
//             let ciphertext = stream_encryptor
//                 .encrypt_next(buffer.as_slice())
//                 .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
//             dist_file.write(&ciphertext)?;
//         } else {
//             let ciphertext = stream_encryptor
//                 .encrypt_last(&buffer[..read_count])
//                 .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
//             dist_file.write(&ciphertext)?;
//             break;
//         }
//     }
//
//     Ok(())
// }
//
// fn decrypt_large_file(
//     encrypted_file_path: &str,
//     dist: &str,
//     key: &[u8; 32],
//     nonce: &[u8; 19],
// ) -> Result<(), anyhow::Error> {
//     let aead = XChaCha20Poly1305::new(key.as_ref().into());
//     let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());
//
//     const BUFFER_LEN: usize = 500 + 16;
//     let mut buffer = [0u8; BUFFER_LEN];
//
//     let mut encrypted_file = File::open(encrypted_file_path)?;
//     let mut dist_file = File::create(dist)?;
//
//     loop {
//         let read_count = encrypted_file.read(&mut buffer)?;
//
//         if read_count == BUFFER_LEN {
//             let plaintext = stream_decryptor
//                 .decrypt_next(buffer.as_slice())
//                 .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
//             dist_file.write(&plaintext)?;
//         } else if read_count == 0 {
//             break;
//         } else {
//             let plaintext = stream_decryptor
//                 .decrypt_last(&buffer[..read_count])
//                 .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
//             dist_file.write(&plaintext)?;
//             break;
//         }
//     }
//
//     Ok(())
// }
