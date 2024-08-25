use anyhow::{Context, Result};
use bip32::{Error as Bip32Error, Mnemonic, Prefix, XPrv};
use bip39::{Error as Bip39Error, Mnemonic as Bip39Mnemonic};
// use bitcoin::hashes::{Hash, hmac, sha512, HashEngine};
use base58::FromBase58;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use clap::Parser;
use hmac::{Hmac, Mac};
use sha2::Digest;
use sha2::Sha256;
use sha2::Sha512;
pub mod cripter;
use crate::cripter::decrypt_small_file_with_rounds;
use crate::cripter::encrypt_small_file_with_rounds;
// use rand_core::OsRng;
// use std::io;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::panic;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

// ANSI escape code for yellow text
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m"; // Reset to default color

static DATABASE_PATH: &str = "mnemonic.db";
const CIPHER_ROUNDS: usize = 4001;

#[derive(Parser)]
#[command(version, long_about = None)]
#[clap(about, version, author)]
struct Args {
    #[clap(short = 'n', long = "name")]
    ///<String> Name of the password. Case insensitive (e.g., servicename@username#no).
    name: Option<String>,

    #[clap(short = 'i', long = "index")]
    ///<u32> Index BIP85
    index: Option<u32>,

    #[clap(short = 'l', long = "length", default_value = "21")]
    ///<u32> Password length
    pwd_len: u32,

    #[clap(short = 'v', long = "verbose", default_value = "false")]
    ///Enable verbose mode. Displays the password index corresponding to the given name. [default: false]
    verbose: bool,

    #[clap(short = 'c', long = "no-clipboard", default_value = "false")]
    ///Prevent copying the password to the clipboard; display it instead. [default: false]
    no_clipboard: bool,

    //     #[clap(short = 'd', long = "decrypt", default_value = "false", help=format!("Decrypt the mnemonic from database. [default: true if password database found] [default file: ~/{}]", DATABASE_PATH))]
    //     ///Decrypt the mnemonic from the database. [default: false] [default file: ~/mnemonic.db]
    //     decrypt: bool,
    #[clap(short = 'e', long = "encrypt", default_value = "false", help=format!("Encrypt the mnemonic into the database instead of decrypting it [default: false] [default file: ~/{}]", DATABASE_PATH))]
    ///Encrypt the mnemonic to the database. [default: false] [default file: ~/mnemonic.db]
    encrypt: bool,

    #[clap(short = 'f', long = "file", help=format!("<String> Path to the password-protected mnemonic database. Used for decryption the mnemonic database by default. Provide an empty argument to omit the default decryption behavior. [default: ~/{}]", DATABASE_PATH))]
    ///<String> Path to the password-protected mnemonic database. Used for decryption the mnemonic database by default. Provide an empty argument to omit the default decryption behavior. [default: ~/mnemonic.db]
    db_path: Option<String>,
}

// use std::hash::{Hash as StdHash, Hasher};
// use std::collections::hash_map::DefaultHasher;
// fn hash_function_default(input: &str) -> u32 {
//     let mut hasher = DefaultHasher::new();
//     StdHash::hash(input, &mut hasher);
//     (hasher.finish() % 10000).try_into().unwrap()
// }

// fn hash_function_fnv(input_string: &str) -> u32 {
//     const PRIME: u32 = 101; // Multiplier, it does not have to be a prime number
//     const STATE_SPACE: u32 = 10000;
//     let mut hash: u32 = 0; // FNV offset basis, may be 0xCAFEBABE to easy remember
//     // Fowler–Noll–Vo (FNV) hash algorithm
//     for ch in input_string.chars() {
//         hash ^= ch as u32;
//         hash = hash.wrapping_mul(PRIME);
//     }
//
//     hash % STATE_SPACE
// }

fn hash_function_polyu32(input_string: &str) -> u32 {
    const PRIME: u32 = 31;
    const STATE_SPACE: u32 = 10000; // Hash space size
    let mut hash: u32 = 0;
    let mut power: u32 = 1;

    for ch in input_string.chars() {
        hash = hash.wrapping_add(power.wrapping_mul(ch as u32));
        power = power.wrapping_mul(PRIME);
    }

    hash % STATE_SPACE
}

// fn hash_function_polyu32_u64internal(input_string: &str) -> u32 {
//     const PRIME: u64 = 31;
//     const STATE_SPACE: u32 = 10000; // Hash space size
//     let mut hash: u64 = 0;
//     let mut power: u64 = 1;
//
//     for ch in input_string.chars() {
//         hash = hash.wrapping_add(power.wrapping_mul(ch as u64));
//         power = power.wrapping_mul(PRIME);
//     }
//
//     (hash % (STATE_SPACE as u64)) as u32 // Cast the final result back to u32
// }

// fn check_mnemonic_database_write_permissions_old() -> std::io::Result<bool> {
//     let mut path = MNEMONIC_DATABASE_NAME;
//     if !Path::new(MNEMONIC_DATABASE_NAME).exists() {
//         path = ".";
//     }
//     // Check if able to write inside directory
//     let md = fs::metadata(path)?;
//     let permissions = md.permissions();
//     Ok(!permissions.readonly())
// }

fn check_mnemonic_database_write_permissions(mnemonic_file: &Path) -> std::io::Result<bool> {
    if mnemonic_file.exists() {
        // Try to open the file with write permissions
        return match fs::OpenOptions::new().write(true).open(mnemonic_file) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        };
    }

    // Check if able to write inside directory
    let md = fs::metadata(".")?;
    let permissions = md.permissions();
    Ok(!permissions.readonly())
}

fn read_input(prompt: &str, masked: bool, allow_empty: bool) -> Result<String, io::Error> {
    let input_line = if masked {
        rpassword::prompt_password(prompt)?
    } else {
        println!("{}", prompt); // Display the custom prompt
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line
    };

    let line = input_line.trim();
    if !allow_empty && line.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Read Input: Empty Input Found",
        ));
    }

    Ok(line.to_string())
}

/// Converts an index to its ordinal representation (1st, 2nd, 3rd, etc.).
///
/// # Parameters
/// - `n`: The index to convert (1-based).
///
/// # Returns
/// - A string representing the ordinal suffix.
fn ordinal_suffix(n: usize) -> String {
    let suffix = match n % 100 {
        11 | 12 | 13 => "th", // Special case for 11th, 12th, 13th
        _ => match n % 10 {
            1 => "st",
            2 => "nd",
            3 => "rd",
            _ => "th",
        },
    };
    format!("{}{}", n, suffix)
}

/// Validates a BIP39 mnemonic phrase.
///
/// # Parameters
/// - `mnemonic_phrase`: A string slice representing the mnemonic phrase to validate.
///
/// # Returns
/// - `bool`: Returns `true` if the mnemonic is valid, `false` otherwise.
fn validate_mnemonic(mnemonic_phrase: &str) -> bool {
    match Bip39Mnemonic::parse(mnemonic_phrase) {
        Ok(_) => true, // Mnemonic is valid
        Err(e) => {
            // Handle different types of errors
            match e {
                Bip39Error::BadWordCount(count) => {
                    println!("Validation Error: Mnemonic Bad word count. Expected a multiple of 6, but got {} words.", count);
                }
                Bip39Error::UnknownWord(index) => {
                    let word = mnemonic_phrase
                        .split_whitespace()
                        .nth(index)
                        .unwrap_or("unknown");
                    let ordinal = ordinal_suffix(index + 1);
                    println!(
                        "Validation Error: Mnemonic Unknown {} word '{}'",
                        ordinal, word
                    );
                }
                Bip39Error::BadEntropyBitCount(count) => {
                    println!("Validation Error: Mnemonic Bad entropy bit count. Expected a multiple of 32 bits, but got {} bits.", count);
                }
                Bip39Error::InvalidChecksum => {
                    println!("Validation Error: The mnemonic has an invalid checksum.");
                }
                Bip39Error::AmbiguousLanguages(ambiguous) => {
                    println!(
                        "Validation Error: The mnemonic can be interpreted as multiple languages."
                    );
                    // Print possible languages
                    for lang in ambiguous.iter() {
                        println!("Possible language: {:?}", lang);
                    }
                }
            }
            false // Mnemonic is invalid
        }
    }
}

fn read_passphrase(require_reentry: bool) -> Result<String> {
    loop {
        let passphrase1 = read_input(
            "Enter passphrase for the BIP39 mnemonic [Empty]:",
            true,
            true,
        )
        .context("Failed to read passphrase")?;

        // If the first passphrase is empty, return it directly
        if passphrase1.is_empty() || !require_reentry {
            return Ok(passphrase1);
        }

        let passphrase2 = read_input("Re-enter passphrase for confirmation:", true, true)
            .context("Failed to read passphrase")?;

        if passphrase1 == passphrase2 {
            return Ok(passphrase1); // Return the validated passphrase
        } else {
            println!("Passphrases do not match. Please try again.");
        }
    }
}

fn read_encryption_password() -> Result<String> {
    loop {
        let password1 = read_input("Password to encrypt the database:", true, false)
            .context("Failed to read password")?;
        let password_confirmation = read_input("Re-enter password for confirmation:", true, false)
            .context("Failed to read password")?;

        if password1 == password_confirmation {
            return Ok(password1); // Return the validated password
        } else {
            println!("Passwords do not match. Please try again.");
        }
    }
}

fn validate_wrapped_encoded_string(encoded: &str) -> Result<bool, String> {
    // Decode the Base58 encoded string
    let decoded = encoded
        .from_base58()
        .map_err(|_| "Failed to decode Base58".to_string())?;

    // Ensure the decoded data is at least 5 bytes (1 byte for payload,version, 4 bytes for checksum)
    if decoded.len() < 5 {
        return Err("Decoded data is too short".to_string());
    }

    // Extract version, payload, and checksum
    //     let version = decoded[0];
    let checksum_bytes = &decoded[decoded.len() - 4..];
    let payload = &decoded[..decoded.len() - 4];

    // Print the extracted variables in the desired format
    //     println!("wrapper");
    //     println!("{{");
    //     println!("    checksum {}", u32::from_be_bytes([checksum_bytes[3], checksum_bytes[2], checksum_bytes[1], checksum_bytes[0]]));
    //     println!("    checksum bytes {:?}", checksum_bytes);
    //     println!("    payload bytes {:?}", &payload[1..]); // Convert payload to hex for readability
    //     println!("    version {}", version);
    //     println!("}}");

    // Calculate the checksum of the payload using double SHA-256
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let hash1 = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(&hash1);
    let hash2 = hasher2.finalize();

    // The checksum is the first 4 bytes of the second SHA256 hash
    let calculated_checksum = &hash2[..4];
    //     println!("calculated checksum {:?}", calculated_checksum);

    // Compare the calculated checksum with the extracted checksum
    if calculated_checksum == checksum_bytes {
        Ok(true)
    } else {
        Err("Invalid data checksum".to_string())
    }
}

fn generate_bip85_password(root_xprv: Xpriv, index: u32, length: u32) -> String {
    let path = DerivationPath::from(vec![
        ChildNumber::Hardened { index: 707764 },
        ChildNumber::from_hardened_idx(length).unwrap(),
        ChildNumber::from_hardened_idx(index).unwrap(),
    ]);

    let secp = bitcoin::secp256k1::Secp256k1::new();
    const BIP85_CHILD_NUMBER: ChildNumber = ChildNumber::Hardened { index: 83696968 };
    //     let bip85_root = root_xprv.ckd_priv(&secp, BIP85_CHILD_NUMBER).unwrap();
    let bip85_root = root_xprv.derive_priv(&secp, &BIP85_CHILD_NUMBER).unwrap();
    let derived = bip85_root.derive_priv(&secp, &path).unwrap();
    //     let mut h = hmac::HmacEngine::<sha512::Hash>::new("bip-entropy-from-k".as_bytes());
    //     h.input(&derived.private_key.to_bytes());
    //     let data = hmac::Hmac::from_engine(h).into_inner().to_vec();
    let mut hmac_sha512 =
        Hmac::<Sha512>::new_from_slice("bip-entropy-from-k".as_bytes()).expect("Invalid key size");
    hmac_sha512.update(&derived.private_key.secret_bytes());
    let data = hmac_sha512.finalize().into_bytes().to_vec();
    let entropy_b64 = STANDARD_NO_PAD.encode(&data[..64]);
    entropy_b64[..length as usize].to_string()
}

fn get_mnemonic_file_path(db_path: Option<String>) -> anyhow::Result<PathBuf> {
    if let Some(path) = db_path {
        // Convert the String to PathBuf
        Ok(PathBuf::from(path))
    } else {
        // Attempt to get the home directory
        let home_dir = env::home_dir()
            .context("Home directory environment variable is not set. Please use the -f option to specify the database path.")?;

        let path = home_dir.join(DATABASE_PATH);
        path.to_str()
            .map(|s| PathBuf::from(s))
            .context("Failed to convert the database path to a string.")
    }
}

fn main() -> anyhow::Result<()> {
    let mut decrypt = false;
    let args = Args::parse();
    let mnemonic_file = get_mnemonic_file_path(args.db_path)?;
    let mnemonic_file_exists = mnemonic_file.exists();
    if !args.encrypt && mnemonic_file_exists {
        decrypt = true;
    }
    let index: Option<u32> = args
        .name
        .clone()
        .map(|n| {
            //assert!(n.is_ascii(), "Argument Error: Name is not ASCII string!");
            let hash = hash_function_polyu32(&n.trim().to_lowercase());
            assert!(
                args.index.is_none() || args.index.unwrap() == hash,
                "Ambiguous Arguments: Index(i={}) do not match to Name('{}'={})!",
                args.index.unwrap(),
                n,
                hash
            );
            Some(hash)
        })
        .or_else(|| {
            Some(args.index.or_else(|| {
                if args.encrypt {
                    Some(0)
                } else {
                    Some(hash_function_polyu32(
                        &read_input("Name of a password:", true, false)
                            .expect("Expected not empty string")
                            .trim()
                            .to_lowercase(),
                    ))
                }
            }))
        })
        .expect("Could not calculate the password index");

    // if index.is_none() {
    //     index = Some(read_input("Name of password:", true, false)?);
    // }
    //
    //     println!("Enter a BIP-32 root key (xprv...) or BIP-39 mnemonic");
    //     if !args.name.is_some() {
    //         args.index = hash_function_polyu32(&args.name.unwrap());
    //     }
    if args.verbose {
        println!("Index: {:?}", index.expect("Index not exist"));
    }

    //     let file_cipher_nonce = [0u8; 24];
    let mut file_cipher_key = [0u8; 32];

    let root_xprv = if decrypt {
        assert!(
            mnemonic_file_exists,
            "No mnemonic database file: {}! Try use -f option to specify database path.",
            mnemonic_file.display()
        );
        let password = read_input("Password to database:", true, true)?;
        let _ = io::stdout().flush();
        //         print!("\x1B[1A\x1B[K"); //TODO: replace to use crate termion
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hashed_password = hasher.finalize();
        file_cipher_key.copy_from_slice(&hashed_password);
        match decrypt_small_file_with_rounds(&mnemonic_file, &file_cipher_key, CIPHER_ROUNDS) {
            std::result::Result::Ok(xpriv) => Xpriv::decode(&xpriv).unwrap(),
            std::result::Result::Err(err) => {
                eprintln!("Decrypt mnemonic error: {}", err);
                return Err(err);
            }
        }
    } else {
        match read_input(
            "Enter a BIP32 Root Key (xprv...) or English 24-word BIP39 mnemonic:",
            true,
            false,
        ) {
            Ok(line) => {
                if line.starts_with("xprv") {
                    //             println!("debug XPRV:            {}", line);
                    Xpriv::from_str(&line)
                        .context("Failed to parse a Xpriv value from a string")
                        .unwrap()
                } else {
                    //         println!("debug  Mnemonic:        {}", &line);
                    validate_mnemonic(&line);
                    let mnemonic = Mnemonic::new(&line, Default::default()).map_err(|e| {
                        let word_count = line.split_whitespace().count();
                        let word_count_msg = if word_count != 24 {
                            format!(" Expected 24 words, got: {}", word_count)
                        } else {
                            String::new()
                        };
                        match e {
                            Bip32Error::Bip39 => {
                                anyhow::anyhow!("BIP39 error: The English language mnemonic is invalid or not properly formatted.{}", word_count_msg)
                            }
                            Bip32Error::Base58 => {
                                anyhow::anyhow!("Base58 error: There was an issue with Base58 encoding.")
                            }
                            Bip32Error::ChildNumber => {
                                anyhow::anyhow!("Child number error: The child number is invalid.")
                            }
                            Bip32Error::Crypto => {
                                anyhow::anyhow!("Cryptographic error: There was a cryptographic issue.")
                            }
                            Bip32Error::Decode => {
                                anyhow::anyhow!("Decode error: There was an issue decoding the input.")
                            }
                            Bip32Error::Depth => {
                                anyhow::anyhow!("Depth error: Maximum derivation depth exceeded.")
                            }
                            Bip32Error::SeedLength => {
                                anyhow::anyhow!("Seed length error: The seed length is invalid.")
                            }
                            // Wildcard pattern to handle any future variants
                            _ => {
                                anyhow::anyhow!("Unknown error occurred: {:?}", e)
                            }
                        }
                    })?; // works only with 24 word mnemonic
                    let passphrase = read_passphrase(args.encrypt)?;
                    if !passphrase.is_empty() {
                        let validation_result = validate_wrapped_encoded_string(&passphrase);
                        if validation_result.is_err() {
                            println!("{}Validation Passphrase Warning: Entered passphrase has no wrapped checksum or it is invalid: {}!{}", YELLOW, validation_result.unwrap_err(), RESET);
                        }
                    }
                    let seed = mnemonic.to_seed(&passphrase);
                    Xpriv::from_str(&XPrv::new(&seed).unwrap().to_string(Prefix::XPRV)).unwrap()
                }
            }
            Err(err) => {
                eprintln!("Error: {}", err);
                return Err(err.into());
            }
        }
    };
    //     else {
    //         let mnemonic = Mnemonic::random(&mut OsRng, Default::default());
    //         println!("     Mnemonic:        {}", &mnemonic.phrase());
    //         let seed = mnemonic.to_seed("");
    //         ExtendedPrivKey::from_str(&XPrv::new(&seed).unwrap().to_string(Prefix::XPRV)).unwrap()
    //     };

    //     assert!(!root_xprv.private_key.key.is_empty(), "No private key!");

    if args.encrypt {
        assert!(
            check_mnemonic_database_write_permissions(&mnemonic_file)?,
            "No write permission to create mnemonic database file!"
        );
        let password = read_encryption_password()?;
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hashed_password = hasher.finalize();
        file_cipher_key.copy_from_slice(&hashed_password); // Ensure the key is 32 bytes
        match encrypt_small_file_with_rounds(
            &root_xprv.encode(),
            &mnemonic_file,
            &file_cipher_key,
            CIPHER_ROUNDS,
        ) {
            std::result::Result::Ok(_) => {
                if mnemonic_file_exists {
                    let filename = mnemonic_file
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("Unknown filename");
                    println!("The mnemonic database file '{}' was overwritten.", filename);
                }
            }
            std::result::Result::Err(e) => {
                eprintln!("Encrypt mnemonic error: {}", e);
                return Err(e.into());
            }
        }
        if args.index.is_none() && args.name.is_none() {
            return Ok(());
        }
    }

    //     println!("     Password Length: {:?}", args.pwd_len);
    //     println!("     Index:           {:?}", args.index);

    let password =
        generate_bip85_password(root_xprv, index.expect("Index not exist"), args.pwd_len);
    if !args.no_clipboard {
        let mut clipboard = panic::catch_unwind(|| {
            clippers::Clipboard::get()
        }).map_err(|_| {
            anyhow::anyhow!("Error getting clipboard: The operation panicked. Try use -c option to display password instead.")
        })?;
        let copy_res = clipboard.write_text(password.clone());
        if copy_res.is_err() {
            println!(
                "Error while copying to clipboard. Try use -c option to display password instead."
            );
        }
        assert_eq!(clipboard.read().unwrap().into_text().unwrap(), password);
        if args.verbose {
            println!("Password copied to the clipboard.");
        }
        sleep(Duration::from_secs(20));
        let _ = clipboard.clear();
    //         println!("debug: clip_res {}", clip_res);
    } else {
        println!("{}", &password);
    }

    Ok(())
}

// Test cases
#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Alphanumeric, Rng};

    #[test]
    fn test_generate_bip85_password() {
        // Example input values
        let root_xprv = Xpriv::from_str("xprv9s21ZrQH143K3i4kfV4tE2qAvhys9WDCpHJXKz2biqWkZwLKma1dzWaqin8CxCKPF3tX2fVRD9tBggJtxvdAxTpKfz8zRUoJZa3S7MtMgwy").unwrap();

        // Test data: index, length, and expected password
        // Coldcard Specifics: https://github.com/Coldcard/firmware/blob/master/docs/bip85-passwords.md
        let test_data = [
            (0, 21, "BSdrypS+J4Wr1q8DWjbFE"),
            (1, 21, "TkDX7d9fnX9FZ9QEpjFDB"),
            (2, 21, "cvfdmoZL3BcIpJ7G+Rb8k"),
            (3, 21, "wsCALdN+GgbSOGyGE9aRN"),
            (4, 21, "HfYbWx7gVmUmb2Bw4o4QD"),
            (5, 21, "vLOf9WPO5QiPbOTEbz/yJ"),
            (6, 21, "1oSUs7Cy3fnpdh/fAS7EK"),
            (7, 21, "seh9WN6mlvPPB5jdVz3xN"),
            (8, 21, "U4RD0R0A0RjpHOFtwnv9k"),
        ];

        for (index, length, expected) in &test_data {
            // Call the function
            let result = generate_bip85_password(root_xprv, *index, *length);

            // Assert that the result matches the expected output
            assert_eq!(result, expected.to_string());
        }
    }

    #[test]
    fn test_clipboard() {
        let mut clipboard = clippers::Clipboard::get();
        let text = "Hello, Rust!";
        // Generate a random alphanumeric string of length 7
        let random_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(3)
            .map(char::from)
            .collect();
        let combined_text = format!("{} {}", text, random_string);
        let _ = clipboard.write_text(combined_text.clone());
        assert_eq!(
            clipboard.read().unwrap().into_text().unwrap(),
            combined_text
        );
    }
}
