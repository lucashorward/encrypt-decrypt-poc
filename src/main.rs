use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use std::io::{self, BufRead};
extern crate rand;
use std::fs::File;
use std::io::Read;
use std::io::prelude::*;

fn main() {
    let file_name = std::env::args().nth(1).expect("no file name given");
    encrypt_file(&file_name);
}

fn encrypt_file(path: &String) -> std::io::Result<()> {
    println!("Enter a key. It has to be EXACTLY 12 characters.");
    let stdin = io::stdin();
    let user_filled_key = stdin.lock().lines().next().unwrap().unwrap(); 
    if user_filled_key.len() != 12 {
        panic!("Key was not 12 characters: {:?}", user_filled_key);
    }
    let gen = generate_string();
    let key = GenericArray::clone_from_slice(gen.as_bytes());
    let aead = Aes256GcmSiv::new(key);
    let nonce = GenericArray::from_slice(user_filled_key.as_bytes());
    let file = get_file_as_byte_vec(path);
    let ciphertext = aead
    .encrypt(nonce, file.as_ref())
    .expect("encryption failure!");
    println!("{:?}", ciphertext);
    let new_path = format!("{}.encrypted", path);
    let mut file = File::create(new_path)?;
    file.write_all(ciphertext.as_ref())?;
    decrypt_value(gen, ciphertext, user_filled_key);
    Ok(())
    // TODO read from file
}

fn decrypt_value(key: String, value: Vec<u8>, nonce_string: String) {
    let generated_key = GenericArray::clone_from_slice(key.as_bytes());
    let aead = Aes256GcmSiv::new(generated_key);
    let nonce = GenericArray::from_slice(nonce_string.as_bytes()); // 96-bits; unique per message
    let plaintext = aead.decrypt(nonce, value.as_ref()).expect("decryption failure!");
    let txt = std::str::from_utf8(&plaintext).unwrap();
    println!("{:?}", txt);
}

fn generate_string() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";
    const PASSWORD_LEN: usize = 32;
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
