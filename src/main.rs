use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use std::io::{self, BufRead};
extern crate rand;
use std::fs::File;
use std::io::Read;
use std::io::prelude::*;

fn main() {
    let action = std::env::args().nth(1).expect("no action given. Please enter \"encrypt\" or \"decrypt\" followed by a path");
    let file_name = std::env::args().nth(2).expect("no file name given");
    if action == "encrypt" {
        encrypt_file(&file_name);
    } else if action == "decrypt" {
        decrypt_file(&file_name);
    } else {
        println!("Unknown action: {}", action);
    }
}

fn encrypt_file(path: &String) {
    println!("Enter a key. It has to be EXACTLY 32 characters.");
    let stdin = io::stdin();
    let user_filled_key = stdin.lock().lines().next().unwrap().unwrap(); 
    if user_filled_key.len() != 32 {
        panic!("Key was not 32 characters: {:?}", user_filled_key);
    }
    let key = GenericArray::clone_from_slice(user_filled_key.as_bytes());
    let aead = Aes256GcmSiv::new(key);
    let gen = generate_string();
    println!("Save this nonce, without it you cannot decrypt!");
    println!("{:?}", gen);
    let nonce = GenericArray::from_slice(gen.as_bytes());
    let file = get_file_as_byte_vec(path);
    let ciphertext = aead
    .encrypt(nonce, file.as_ref())
    .expect("encryption failure!");
    write_to_file(path, ciphertext);
}

fn decrypt_file(path: &String) {
    println!("Enter your 32-character key");
    let stdin = io::stdin();
    let user_filled_key = stdin.lock().lines().next().unwrap().unwrap(); 
    if user_filled_key.len() != 32 {
        panic!("Key was not 32 characters: {:?}", user_filled_key);
    }
    println!("Enter your 12-character random nonce");
    let nonce = stdin.lock().lines().next().unwrap().unwrap(); 
    if nonce.len() != 12 {
        panic!("Key was not 12 characters: {:?}", user_filled_key);
    }
    let file = get_file_as_byte_vec(path);
    let val = decrypt_value(user_filled_key, file, nonce);
    write_to_file(path, val);
}

fn write_to_file(path: &String, data: Vec<u8>) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data.as_ref())?;
    Ok(())
}

fn decrypt_value(key: String, value: Vec<u8>, nonce_string: String) -> Vec<u8> {
    let generated_key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = Aes256GcmSiv::new(generated_key);
    let nonce = GenericArray::from_slice(nonce_string.as_bytes()); // 96-bits; unique per message
    aead.decrypt(nonce, value.as_ref()).expect("decryption failure!")
}

fn generate_string() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";
    const PASSWORD_LEN: usize = 12;
    let mut rng = rand::thread_rng();

    let password: String = (0..PASSWORD_LEN)
        .map(|_| {
            let idx = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    println!("{:?}", password);
    return password;
}

fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = std::fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");
    buffer
}
