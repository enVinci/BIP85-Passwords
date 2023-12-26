use bip32::{Mnemonic, Prefix, XPrv};
use bitcoin::hashes::Hash;
use bitcoin::hashes::{hmac, sha512, HashEngine};
use bitcoin::util::bip32::ChildNumber;
use bitcoin::util::bip32::DerivationPath;
use bitcoin::util::bip32::ExtendedPrivKey;
use clap::Parser;
// use rand_core::OsRng;
// use std::io;
use std::str::FromStr;
pub mod cripter;
use crate::cripter::encrypt_small_file;
use crate::cripter::decrypt_small_file;
use std::io::Write;
use std::path::Path;
use std::fs;

const MNEMONIC_DATABASE_NAME: &str = "mnemonic.db";

#[derive(Parser)]
#[command(version, long_about = None)]

#[clap(about, version, author)]
struct Args {
    #[clap(short = 'n', long = "name")]
    ///Nick or (user)name <String>
    name: Option<String>,

    #[clap(short = 'i', long = "index")]
    ///Index BIP85 <u32> [default: 0]
    index: Option<u32>,

    #[clap(short = 'l', long = "length", default_value = "21")]
    ///Password length <u32>
    pwd_len: u32,

    #[clap(short = 'v', long = "verbose", default_value = "false")]
    ///Verbose mode. Always show password index.
    verbose: bool,

    #[clap(short = 'd', long = "decrypt", default_value = "false")]
    ///Decrypt mnemonic from file [file: mnemonic.db]
    decrypt: bool,

    #[clap(short = 'e', long = "encrypt", default_value = "false")]
    ///Encrypt mnemonic to file [file: mnemonic.db]
    encrypt: bool,
}

const P1: u32 = 31;
const M1: u32 = 1e4 as u32;

fn compute_hash(s: &str) -> u32 {
    let mut hash = 0;
    let mut p_pow = 1;
    for ch in s.chars() {
        hash = (hash + (ch as u32 + 1 - ' ' as u32) * p_pow) % M1;
        p_pow = (p_pow * P1) % M1;
//         println!("{} \n", (ch as u32 + 1 - ' ' as u32));
    }
    hash
}

fn check_mnemonic_base_write_perm() -> std::io::Result<bool> {
    let mut path = MNEMONIC_DATABASE_NAME;
    if !Path::new(MNEMONIC_DATABASE_NAME).exists() {
        path = ".";
    }
    // Check if able to write inside directory
    let md = fs::metadata(path)?;
    let permissions = md.permissions();
    Ok(!permissions.readonly())
}

fn main() -> std::io::Result<()> {
    let mut args = Args::parse();
    match args.name {
        Some(ref n) => { assert!(n.is_ascii(), "Option: Name is not ASCII string!");
                    let hash = compute_hash(&n.as_str());
                    assert!(args.index.is_none() || args.index.unwrap() == hash, "Ambiguous Option: Indexes do not match (i={} != {}(aka '{}'))!", args.index.unwrap(), hash, n);
                    args.index = Some(hash) },
        None => assert!(true)
    }

    let mut index : u32 = 0;
    match args.index {
        Some(idx) => index = idx,
        None => assert!(true)
    }
//
//     println!("Enter a BIP-32 root key (xprv...) or BIP-39 mnemonic");
//     if !args.name.is_some() {
//         args.index = compute_hash(&args.name.unwrap());
//     }
    if args.verbose {
        println!("Index: {:?}", index);
    }
    let mut line = String::new();

    let small_file_nonce = [0u8; 24];
    let mut small_file_key = [0u8; 32];
    if args.decrypt {
        assert!(Path::new(MNEMONIC_DATABASE_NAME).exists(), "No mnemonic database file: {}!", MNEMONIC_DATABASE_NAME);
        let password = rpassword::prompt_password("Your password to database: ")?;
        let mut test: &mut[u8] = &mut small_file_key;
        test.write(password.as_bytes())?;
        match decrypt_small_file(MNEMONIC_DATABASE_NAME, &small_file_key, &small_file_nonce) {
            std::result::Result::Ok(mnem) => line = mnem,
            std::result::Result::Err(e) => assert!(false, "Decrypt mnemonic error: {}", e)
        }
    }
    else {
        println!("Enter a BIP-32 root key (xprv...) or 24 word BIP-39 mnemonic");
        let b1 = std::io::stdin().read_line(&mut line)?;
        assert!(b1 > 0, "No mnemonic input!");
    }

    let line = line.as_str().trim();
    let root_xprv = if line.starts_with("xprv") {
//         println!("debug XPRV:            {}", line);
        ExtendedPrivKey::from_str(&line).unwrap()
    } else {
        assert!(!line.is_empty(), "Empty mnemonic");
//         println!("debug  Mnemonic:        {}", &line);
        let mnemonic = Mnemonic::new(&line, Default::default()).unwrap();
        let seed = mnemonic.to_seed("");
        ExtendedPrivKey::from_str(&XPrv::new(&seed).unwrap().to_string(Prefix::XPRV)).unwrap()
    };
//     else {
//         let mnemonic = Mnemonic::random(&mut OsRng, Default::default());
//         println!("     Mnemonic:        {}", &mnemonic.phrase());
//         let seed = mnemonic.to_seed("");
//         ExtendedPrivKey::from_str(&XPrv::new(&seed).unwrap().to_string(Prefix::XPRV)).unwrap()
//     };

    assert!(!root_xprv.private_key.key.is_empty(), "No private key!");

    if args.encrypt {
        assert!(check_mnemonic_base_write_perm()?, "No write permission to create mnemonic database file!");
        let password = rpassword::prompt_password("Your password to database: ")?;
        let mut test: &mut[u8] = &mut small_file_key;
        test.write(password.as_bytes())?;
        match encrypt_small_file(&line, MNEMONIC_DATABASE_NAME, &small_file_key, &small_file_nonce) {
            std::result::Result::Ok(_) => assert!(true),
            std::result::Result::Err(e) => assert!(false, "Encrypt mnemonic error: {}", e)
        }
        if args.index.is_none() && args.name.is_none() {
            return Ok(())
        }
    }

//     println!("     Password Length: {:?}", args.pwd_len);
//     println!("     Index:           {:?}", args.index);

    let path = DerivationPath::from(vec![
        ChildNumber::Hardened { index: 707764 },
        ChildNumber::from_hardened_idx(args.pwd_len).unwrap(),
        ChildNumber::from_hardened_idx(index).unwrap(),
    ]);

    let secp = bitcoin::secp256k1::Secp256k1::new();
    const BIP85_CHILD_NUMBER: ChildNumber = ChildNumber::Hardened { index: 83696968 };
    let bip85_root = root_xprv.ckd_priv(&secp, BIP85_CHILD_NUMBER).unwrap();
    let derived = bip85_root.derive_priv(&secp, &path).unwrap();
    let mut h = hmac::HmacEngine::<sha512::Hash>::new("bip-entropy-from-k".as_bytes());
    h.input(&derived.private_key.to_bytes());
    let data = hmac::Hmac::from_engine(h).into_inner().to_vec();
    let entropy_b64 = base64::encode(&data[0..64]);
    let password = entropy_b64[0..args.pwd_len as usize].to_string();

//     println!("\n");
//     println!("Password: {}", &password);
    println!("{}", &password);
//     println!("\n");
    Ok(())
}
