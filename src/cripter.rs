use anyhow::anyhow;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};
use std::path::Path;
use std::{
    fs::{self, File},
    io::Read,
};

pub fn encrypt_small_file(
    data: &[u8],
    filepath: &Path,
    key: &[u8; 32],
    nonce: &[u8; 24], //192-bit (24-byte) nonce.
) -> Result<(), anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut buffer: Vec<u8> = Vec::with_capacity(256);
    buffer.extend_from_slice(data);
    //     buffer.extend([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    //     let mut ciphertext = cipher
    //             .encrypt(nonce.into(), data.as_ref())
    //             .map_err(|err| anyhow!("Encrypting file: {}", err))?;
    cipher
        .encrypt_in_place(nonce.into(), b"", &mut buffer)
        .map_err(|err| anyhow!("Encrypting file: {}", err))?;

    //     println!("buffer len {}", buffer.len());
    fs::write(&filepath, buffer)?;

    Ok(())
}

pub fn decrypt_small_file(
    encrypted_file_path: &Path,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, std::io::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut file = File::open(encrypted_file_path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(256);
    file.read_to_end(&mut buffer)?;

    match cipher.decrypt_in_place(nonce.into(), b"", &mut buffer) {
        Ok(_) => Ok(buffer),
        Err(err) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Decrypting file: {}", err),
        )),
    }
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

// Test module for encrypt_small_file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_small_file() {
        // Arrange
        let data = b"Hello, world!";
        let filepath = Path::new("cargo_test_encrypt_decrypt_file.db");
        let key: [u8; 32] = [0; 32];
        let nonce: [u8; 24] = [0; 24];

        // Encrypt
        let result = encrypt_small_file(data, filepath, &key, &nonce);
        // Assert
        assert!(result.is_ok());

        // Decrypt
        let decrypted_data = decrypt_small_file(&filepath, &key, &nonce);
        // Assert
        assert!(decrypted_data.is_ok());
        assert_eq!(decrypted_data.unwrap(), data);

        //Encrypted file size check for 16-bytes overhead for auth tag
        let mut file = File::open(filepath).expect("Failed to open file");
        let mut buffer: Vec<u8> = Vec::with_capacity(256);
        file.read_to_end(&mut buffer)
            .expect("Failed to read from file");
        assert_eq!(buffer.len(), data.len() + 16);

        // Clean up: Remove the file
        std::fs::remove_file(filepath).expect("Failed to remove file");
    }

    #[test]
    fn test_encrypt_small_file() {
        // Arrange
        let data = b"Hello, world!";
        let filepath = Path::new("cargo_test_encrypt_file.db");
        let key: [u8; 32] = [0; 32];
        let nonce: [u8; 24] = [0; 24];

        // Encrypt
        let result = encrypt_small_file(data, filepath, &key, &nonce);
        assert!(result.is_ok());

        // Read
        let mut file = File::open(filepath).expect("Failed to open file");
        let mut buffer: Vec<u8> = Vec::with_capacity(256);
        file.read_to_end(&mut buffer)
            .expect("Failed to read from file");
        assert_ne!(buffer, data);

        // Clean up: Remove the file
        std::fs::remove_file(filepath).expect("Failed to remove file");
    }

    #[test]
    fn test_write_read_compare_file() {
        // Arrange
        let data = b"Hello, world!";
        let filepath = Path::new("cargo_test_write_read_file.db");

        // Write
        let mut buffer_write: Vec<u8> = Vec::with_capacity(256);
        buffer_write.extend_from_slice(data);
        fs::write(&filepath, buffer_write.clone()).expect("Failed to write to file");
        assert_eq!(buffer_write, data);

        // Read
        let mut file = File::open(filepath).expect("Failed to open file");
        let mut buffer: Vec<u8> = Vec::with_capacity(256);
        file.read_to_end(&mut buffer)
            .expect("Failed to read from file");
        assert_eq!(buffer, data);
        assert!(
            !buffer.is_empty(),
            "Buffer size should be greater than zero"
        );

        // Clean up: Remove the file
        std::fs::remove_file(filepath).expect("Failed to remove file");
    }

    #[test]
    fn test_vec_buffer() {
        let data = b"Hello, world!";
        let mut buffer: Vec<u8> = vec![0_u8; 128];
        buffer.extend_from_slice(data);
        assert_eq!(&buffer[..128], vec![0_u8; 128]);
        assert_eq!(&buffer[128..141], data);
    }

    #[test]
    fn test_vec_buffer_with_capacity() {
        let data = b"Hello, world!";
        let mut buffer: Vec<u8> = Vec::with_capacity(256);
        buffer.extend_from_slice(data);
        assert_eq!(&buffer, data);
    }
}
