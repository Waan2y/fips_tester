pub mod sha;
pub mod hmac;
pub mod aes;
pub mod hmac_drbg;
pub mod kdf;
pub mod ecdsa;
pub mod eddsa;
pub mod rsa;
pub mod ml_kem;
pub mod ml_dsa;

use crate::runner::AlgoTester;

/// Map an algorithm CLI key to its tester.
/// Returns None if no tester is implemented yet for that key.
pub fn make_tester(algo_key: &str) -> Option<Box<dyn AlgoTester>> {
    match algo_key {
        "sha2-256" | "sha2-384" | "sha2-512"
        | "sha3-256" | "sha3-384" | "sha3-512"
        | "shake-128" | "shake-256" => Some(Box::new(sha::ShaTester::new(algo_key))),

        "hmac-sha2-256" | "hmac-sha2-384" | "hmac-sha2-512"
        | "hmac-sha3-256" | "hmac-sha3-384" | "hmac-sha3-512" => {
            Some(Box::new(hmac::HmacTester::new(algo_key)))
        }

        "aes-ecb" | "aes-cbc" | "aes-ctr" | "aes-gcm" => {
            Some(Box::new(aes::AesTester::new(algo_key)))
        }

        "hmacdrbg" => Some(Box::new(hmac_drbg::HmacDrbgTester::new())),
        "kdf" => Some(Box::new(kdf::KdfTester::new())),

        "ecdsa-keygen" | "ecdsa-keyver" | "ecdsa-siggen" | "ecdsa-sigver" => {
            Some(Box::new(ecdsa::EcdsaTester::new(algo_key)))
        }

        "eddsa-keygen" | "eddsa-siggen" | "eddsa-sigver" => {
            Some(Box::new(eddsa::EddsaTester::new(algo_key)))
        }

        "rsa-keygen" | "rsa-siggen" | "rsa-sigver" => {
            Some(Box::new(rsa::RsaTester::new(algo_key)))
        }

        "ml-kem-keygen" | "ml-kem-encapdecap" => {
            Some(Box::new(ml_kem::MlKemTester::new(algo_key)))
        }

        "ml-dsa-keygen" | "ml-dsa-siggen" | "ml-dsa-sigver" => {
            Some(Box::new(ml_dsa::MlDsaTester::new(algo_key)))
        }

        _ => None,
    }
}
