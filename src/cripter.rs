use anyhow::anyhow;
use anyhow::{Context, Result};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};
use rand::RngCore;
use std::path::Path;
use std::{
    fs::{self, File},
    io::Read,
    io::Write,
};

pub fn encrypt_small_file(
    data: &[u8],
    filepath: &Path,
    key: &[u8; 32],
) -> Result<(), anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    // Generate a random nonce
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Create a buffer to hold the encrypted data
    let mut buffer = Vec::with_capacity(data.len() + nonce.len());
    buffer.extend_from_slice(&nonce); // Prepend nonce to the buffer

    // Encrypt the data
    let mut data_to_encrypt = data.to_vec();
    cipher
        .encrypt_in_place(&nonce.into(), b"", &mut data_to_encrypt)
        .map_err(|err| anyhow!("Encrypting file: {}", err))?;

    // Append the encrypted data to the buffer
    buffer.extend_from_slice(&data_to_encrypt);

    // Write the buffer to the file
    fs::write(filepath, buffer)?;

    Ok(())
}

pub fn decrypt_small_file(
    encrypted_file_path: &Path,
    key: &[u8; 32],
) -> Result<Vec<u8>, anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut file = File::open(encrypted_file_path).context("Opening encrypted file")?;

    // Read the entire file into a buffer
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .context("Reading encrypted file")?;

    // Extract the nonce from the beginning of the buffer
    let (nonce, encrypted_data) = buffer.split_at(24);

    // Decrypt the data
    let mut decrypted_data = encrypted_data.to_vec();
    cipher
        .decrypt_in_place(nonce.into(), b"", &mut decrypted_data)
        .map_err(|err| anyhow!("Decrypting file: {}", err))?;

    Ok(decrypted_data)
}

pub fn encrypt_small_file_with_rounds(
    data: &[u8],
    filepath: &Path,
    key: &[u8; 32],
    rounds: usize,
) -> Result<(), anyhow::Error> {
    // Check if rounds is greater than 0
    if rounds == 0 {
        return Err(anyhow!("Number of rounds must be greater than 0."));
    }

    let mut encrypted_data = data.to_vec();

    for _ in 0..rounds {
        // Create a new cipher instance for each round
        let cipher = XChaCha20Poly1305::new(key.into());

        // Generate a random nonce
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Create a buffer to hold the encrypted data
        let mut buffer = Vec::with_capacity(encrypted_data.len() + nonce.len());
        buffer.extend_from_slice(&nonce); // Prepend nonce to the buffer

        // Encrypt the data
        cipher
            .encrypt_in_place(&nonce.into(), b"", &mut encrypted_data)
            .map_err(|err| anyhow!("Encrypting file: {}", err))?;

        // Append the encrypted data to the buffer
        buffer.extend_from_slice(&encrypted_data);

        // Update encrypted_data for the next round
        encrypted_data = buffer.clone(); // Use the newly encrypted data for the next round
    }

    // Write the final encrypted data to the file after all rounds
    let mut file = File::create(filepath).context("Creating encrypted file")?;
    file.write_all(&encrypted_data)
        .context("Writing encrypted data to file")?;

    // Sync the file to ensure data is written to permanent storage
    file.sync_all().context("Syncing file to disk")?;

    Ok(())
}

pub fn decrypt_small_file_with_rounds(
    encrypted_file_path: &Path,
    key: &[u8; 32],
    rounds: usize,
) -> Result<Vec<u8>, anyhow::Error> {
    // Check if rounds is greater than 0
    if rounds == 0 {
        return Err(anyhow!("Number of rounds must be greater than 0."));
    }

    // Read the encrypted file
    let mut file = File::open(encrypted_file_path).context("Opening encrypted file")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .context("Reading encrypted file")?;

    // Decrypt in reverse order
    for _ in 0..rounds {
        // Extract the nonce from the beginning of the buffer
        let (nonce, encrypted_data) = buffer.split_at(24);

        // Create a new cipher instance for each round
        let cipher = XChaCha20Poly1305::new(key.into());

        // Decrypt the data
        let mut data_to_decrypt = encrypted_data.to_vec();
        cipher
            .decrypt_in_place(nonce.into(), b"", &mut data_to_decrypt)
            .map_err(|err| anyhow!("Decrypting file: {}", err))?;

        // Update buffer for the next round
        buffer = data_to_decrypt;
    }

    // Remove the nonce from the final decrypted data
    Ok(buffer)
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
        let key: [u8; 32] = [0; 32]; // Use a fixed key for testing

        // Encrypt
        let result = encrypt_small_file(data, filepath, &key);
        // Assert
        assert!(result.is_ok());

        // Decrypt
        let decrypted_data = decrypt_small_file(&filepath, &key);
        // Assert
        assert!(decrypted_data.is_ok());
        assert_eq!(decrypted_data.unwrap(), data);

        //Encrypted file size check for 16-bytes overhead for auth tag
        let mut file = File::open(filepath).expect("Failed to open file");
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer)
            .expect("Failed to read from file");
        assert_eq!(buffer.len(), data.len() + 24 + 16); // 24 bytes for nonce + 16 bytes for auth tag

        // Clean up: Remove the file
        std::fs::remove_file(filepath).expect("Failed to remove file");
    }

    #[test]
    fn test_encrypt_small_file() {
        // Test if payload is encrypted
        // Arrange
        let data = b"Hello, world!";
        let filepath = Path::new("cargo_test_encrypt_file.db");
        let key: [u8; 32] = [0; 32]; // Use a fixed key for testing

        // Encrypt
        let result = encrypt_small_file(data, filepath, &key);
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
