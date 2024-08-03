use bip32::{Mnemonic, Prefix, XPrv};
// use bitcoin::hashes::{Hash, hmac, sha512, HashEngine};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use clap::Parser;
use hmac::{Hmac, Mac};
use sha2::Sha512;
// use rand_core::OsRng;
// use std::io;
use std::str::FromStr;
pub mod cripter;
use crate::cripter::decrypt_small_file;
use crate::cripter::encrypt_small_file;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::env;
use std::thread::sleep;
use std::time::Duration;

static DATABASE_PATH: &str = "mnemonic.db";

#[derive(Parser)]
#[command(version, long_about = None)]
#[clap(about, version, author)]
struct Args {
    #[clap(short = 'n', long = "name")]
    ///Name of password <String>. Case insensitive (e.g. service name @ username % no.).
    name: Option<String>,

    #[clap(short = 'i', long = "index")]
    ///Index BIP85 <u32> [default: 0]
    index: Option<u32>,

    #[clap(short = 'l', long = "length", default_value = "21")]
    ///Password length <u32>
    pwd_len: u32,

    #[clap(short = 'v', long = "verbose", default_value = "false")]
    ///Verbose mode. shows password index. [default: false]
    verbose: bool,

    #[clap(short = 'c', long = "no-clipboard", default_value = "false")]
    ///Prevent coping password to the clipboard, display password instead. [default: false]
    no_clipboard: bool,

    #[clap(short = 'd', long = "decrypt", default_value = "false", help=format!("Decrypt mnemonic from file [file: ~/{}]", DATABASE_PATH))]
    ///Decrypt mnemonic from file. [default: false] [file: ~/mnemonic.db]
    decrypt: bool,

    #[clap(short = 'e', long = "encrypt", default_value = "false", help=format!("Encrypt mnemonic to file [file: ~/{}]", DATABASE_PATH))]
    ///Encrypt mnemonic to file. [default: false] [file: ~/mnemonic.db]
    encrypt: bool,

    #[clap(short = 'f', long = "file", help=format!("Path to password database. <String> [default: ~/{}]", DATABASE_PATH))]
    ///Path to password database <String>. [default: ~/mnemonic.db]
    file: Option<String>,
}

// use std::hash::{Hash as StdHash, Hasher};
// use std::collections::hash_map::DefaultHasher;
// fn hash_function_default(input: &str) -> u32 {
//     let mut hasher = DefaultHasher::new();
//     StdHash::hash(input, &mut hasher);
//     (hasher.finish() % 10000).try_into().unwrap()
// }

fn hash_function(input_string: &str) -> u32 {
    const PRIME: u32 = 101;
    const STATE_SPACE: u32 = 1e4 as u32;
    let mut hash: u32 = 0;
    //     let mut p_pow = 1;
    // Fowler–Noll–Vo (FNV) hash algorithm
    for ch in input_string.chars() {
        hash ^= ch as u32;
        hash = hash.wrapping_mul(PRIME);
        //         hash = (hash + (ch as u32 + 1 - ' ' as u32) * p_pow) % STATE_SPACE;
        //         p_pow = (p_pow * PRIME) % STATE_SPACE;
    }
    hash % STATE_SPACE
}

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
            "Empty Input Found",
        ));
    }

    Ok(line.to_string())
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

fn main() -> std::io::Result<()> {
    let mut args = Args::parse();
    let mnemonic_file_string = if args.file.is_some() {
        if !args.decrypt && !args.encrypt {
            args.decrypt = true;
        }
        args.file.unwrap()
    } else {
        Path::new(&env::home_dir().expect("home dir env not specified. Try use -f option to specify database path.").into_os_string().into_string().expect("conversion String")).join(DATABASE_PATH).to_str().expect("conversion Path to str failed").to_string()
    };
    let mnemonic_file = Path::new(&mnemonic_file_string);
    let index: Option<u32> = args
        .name
        .clone()
        .map(|n| {
            //assert!(n.is_ascii(), "Argument Error: Name is not ASCII string!");
            let hash = hash_function(&n.trim().to_lowercase());
            assert!(
                args.index.is_none() || args.index.unwrap() == hash,
                "Ambiguous Arguments: Index(i={}) do not match to Name('{}'(={}))!",
                args.index.unwrap(),
                n,
                hash
            );
            Some(hash)
        })
        .or_else(|| {
            Some(args.index.or_else(|| {
                Some(hash_function(
                    &read_input("Name of a password:", true, false)
                        .expect("Expected not empty string")
                        .trim()
                        .to_lowercase(),
                ))
            }))
        })
        .expect("Could not calculate the password index");

    // if index.is_none() {
    //     index = Some(read_input("Name of password:", true, false)?);
    // }
    //
    //     println!("Enter a BIP-32 root key (xprv...) or BIP-39 mnemonic");
    //     if !args.name.is_some() {
    //         args.index = hash_function(&args.name.unwrap());
    //     }
    if args.verbose {
        println!("Index: {:?}", index.expect("Index not exist"));
    }

    let file_cipher_nonce = [0u8; 24];
    let mut file_cipher_key = [0u8; 32];

    let root_xprv = if args.decrypt {
        assert!(
            mnemonic_file.exists(),
            "No mnemonic database file: {}! Try use -f option to specify database path.",
            mnemonic_file.display()
        );
        let password = read_input("Password to database:", true, true)?;
        let _ = io::stdout().flush();
        //         print!("\x1B[1A\x1B[K"); //TODO: replace to use crate termion
        let mut test: &mut [u8] = &mut file_cipher_key;
        test.write(password.as_bytes())?;
        match decrypt_small_file(mnemonic_file, &file_cipher_key, &file_cipher_nonce) {
            std::result::Result::Ok(xpriv) => Xpriv::decode(&xpriv).unwrap(),
            std::result::Result::Err(err) => {
                eprintln!("Decrypt mnemonic error: {}", err);
                return Err(err);
            }
        }
    } else {
        match read_input(
            "Enter a BIP-32 root key (xprv...) or 24-word BIP-39 mnemonic:",
            true,
            false,
        ) {
            Ok(line) => {
                if line.starts_with("xprv") {
                    //             println!("debug XPRV:            {}", line);
                    Xpriv::from_str(&line).unwrap()
                } else {
                    //         println!("debug  Mnemonic:        {}", &line);
                    let mnemonic = Mnemonic::new(&line, Default::default()).unwrap(); // works only with 24 word mnemonic
                    match read_input(
                        "Enter passphrase for the BIP-39 mnemonic [Empty]:",
                        true,
                        true,
                    ) {
                        Ok(passphrase) => {
                            let seed = mnemonic.to_seed(&passphrase);
                            Xpriv::from_str(&XPrv::new(&seed).unwrap().to_string(Prefix::XPRV))
                                .unwrap()
                        }
                        Err(err) => {
                            eprintln!("Passphrase Error: {}", err);
                            return Err(err);
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!("Error: {}", err);
                return Err(err);
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
            check_mnemonic_database_write_permissions(mnemonic_file)?,
            "No write permission to create mnemonic database file!"
        );
        let password = read_input("Your password to encrypt database:", true, false)?;
        let mut test: &mut [u8] = &mut file_cipher_key;
        test.write(password.as_bytes())?;
        match encrypt_small_file(
            &root_xprv.encode(),
            mnemonic_file,
            &file_cipher_key,
            &file_cipher_nonce,
        ) {
            std::result::Result::Ok(_) => {}
            std::result::Result::Err(e) => assert!(false, "Encrypt mnemonic error: {}", e),
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
        let mut clipboard = clippers::Clipboard::get();
        let copy_res = clipboard.write_text(password.clone());
        if copy_res.is_err() {
            println!("Error while coping to clipboard. Try use -c option to display password instead.");
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
