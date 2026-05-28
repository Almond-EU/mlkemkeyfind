use ml_kem::{
    KeyExport, MlKem768,
    kem::{Encapsulate, Kem}
};
use std::fs::File;
use std::io::Write;

fn main() {
    {
        // Generate key and save public key
        let (_, ek) = MlKem768::generate_keypair();
        let mut file = File::create("pub.bin").expect("Cannot create public key file");
        file.write_all(&ek.to_bytes()).expect("Error writing public key");

        // Encapsulation and save ciphertext
        let (ct, _) = ek.encapsulate();
        let mut file = File::create("ct.bin").expect("Cannot create ciphertext file");
        file.write_all(&ct.0).expect("Error writing ciphertext");
    }

    // Pause
    std::io::stdin().read_line(&mut String::new()).expect("Error reading line");
}
