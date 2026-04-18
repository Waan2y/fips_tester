pub mod sha;
// pub mod hmac;   // uncomment when implemented
// pub mod aes;    // uncomment when implemented
// pub mod ecdsa;  // uncomment when implemented

use crate::runner::AlgoTester;

/// Map an algorithm CLI key to its tester.
/// Returns None if no tester is implemented yet for that key.
pub fn make_tester(algo_key: &str) -> Option<Box<dyn AlgoTester>> {
    match algo_key {
        "sha2-256" | "sha2-384" | "sha2-512"
        | "sha3-256" | "sha3-384" | "sha3-512"
        | "shake-128" | "shake-256" => Some(Box::new(sha::ShaTester::new(algo_key))),

        // Future entries — add one line per family here:
        // "hmac-sha2-256" | "hmac-sha2-384" | ... => Some(Box::new(hmac::HmacTester::new(algo_key))),
        // "aes-ecb" | "aes-cbc" | ...             => Some(Box::new(aes::AesTester::new(algo_key))),
        _ => None,
    }
}
