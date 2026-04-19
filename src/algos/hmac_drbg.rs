use std::path::Path;

use anyhow::Context as _;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

use crate::runner::{AlgoTester, TestFailure, TestSummary};
use crate::testvec::{load_expected, load_prompt};

pub struct HmacDrbgTester;

impl HmacDrbgTester {
    pub fn new() -> Self { Self }
}

impl AlgoTester for HmacDrbgTester {
    fn run(&self, vec_dir: &Path) -> anyhow::Result<TestSummary> {
        let prompt = load_prompt(vec_dir)?;
        let expected = load_expected(vec_dir)?;

        println!("Testing hmacdrbg...");

        let mut summary = TestSummary {
            algo: "hmacdrbg".to_string(),
            total: 0,
            passed: 0,
            failures: Vec::new(),
        };

        // Index expected tests by (tgId, tcId)
        let mut exp: std::collections::HashMap<(u64, u64), String> = std::collections::HashMap::new();
        for g in &expected.test_groups {
            let tg_id = g["tgId"].as_u64().unwrap_or(0);
            for t in g["tests"].as_array().into_iter().flatten() {
                let tc_id = t["tcId"].as_u64().unwrap_or(0);
                if let Some(rb) = t["returnedBits"].as_str() {
                    exp.insert((tg_id, tc_id), rb.to_string());
                }
            }
        }

        let mut result_groups: Vec<serde_json::Value> = Vec::new();

        for g in prompt.test_groups {
            let tg_id = g["tgId"].as_u64().unwrap_or(0);
            let mode = g["mode"].as_str().unwrap_or("SHA-1").to_string();
            let pred_resist = g["predResistance"].as_bool().unwrap_or(false);
            let returned_bits_len = g["returnedBitsLen"].as_u64().unwrap_or(0) as usize;
            let tests = g["tests"].as_array().cloned().unwrap_or_default();

            let mut group_pass = 0usize;
            let total_in_group = tests.len();
            let mut result_tests: Vec<serde_json::Value> = Vec::new();

            for t in tests {
                let tc_id = t["tcId"].as_u64().unwrap_or(0);
                summary.total += 1;

                let result = (|| -> anyhow::Result<Vec<u8>> {
                    let entropy = hex::decode(t["entropyInput"].as_str().unwrap_or(""))?;
                    let nonce = hex::decode(t["nonce"].as_str().unwrap_or(""))?;
                    let perso = hex::decode(t["persoString"].as_str().unwrap_or(""))?;

                    let mut drbg = HmacDrbg::new(&mode, &entropy, &nonce, &perso)?;
                    let mut last_output = Vec::new();

                    for oi in t["otherInput"].as_array().into_iter().flatten() {
                        let use_kind = oi["intendedUse"].as_str().unwrap_or("");
                        let addl = hex::decode(oi["additionalInput"].as_str().unwrap_or(""))?;
                        let ei_str = oi["entropyInput"].as_str().unwrap_or("");
                        let ei = if ei_str.is_empty() { Vec::new() } else { hex::decode(ei_str)? };

                        if use_kind.eq_ignore_ascii_case("reSeed") {
                            drbg.reseed(&ei, &addl)?;
                        } else if use_kind.eq_ignore_ascii_case("generate") {
                            if pred_resist {
                                drbg.reseed(&ei, &addl)?;
                                last_output = drbg.generate(&[], returned_bits_len)?;
                            } else {
                                last_output = drbg.generate(&addl, returned_bits_len)?;
                            }
                        } else {
                            anyhow::bail!("unknown intendedUse '{}'", use_kind);
                        }
                    }
                    Ok(last_output)
                })();

                match result {
                    Ok(bits) => {
                        let actual = hex::encode_upper(&bits);
                        result_tests.push(serde_json::json!({"tcId": tc_id, "returnedBits": actual.clone()}));
                        let expected = exp.get(&(tg_id, tc_id)).cloned().unwrap_or_default();
                        if actual.eq_ignore_ascii_case(&expected) {
                            summary.passed += 1;
                            group_pass += 1;
                        } else {
                            summary.failures.push(TestFailure {
                                tg_id, tc_id,
                                detail: "returnedBits mismatch".into(),
                            });
                        }
                    }
                    Err(e) => {
                        result_tests.push(serde_json::json!({"tcId": tc_id}));
                        summary.failures.push(TestFailure {
                            tg_id, tc_id,
                            detail: format!("error: {e}"),
                        });
                    }
                }
            }

            println!("  AFT  [tgId={tg_id} mode={mode}]: {}/{} passed", group_pass, total_in_group);
            result_groups.push(serde_json::json!({"tgId": tg_id, "tests": result_tests}));
        }

        let result_file = serde_json::json!({
            "vsId": expected.vs_id,
            "algorithm": expected.algorithm,
            "revision": expected.revision,
            "isSample": expected.is_sample,
            "testGroups": result_groups,
        });
        std::fs::write(
            vec_dir.join("result.json"),
            serde_json::to_string_pretty(&result_file).context("serialize")?,
        )?;

        Ok(summary)
    }
}

// ---------------------------------------------------------------------------
// HMAC-DRBG per SP 800-90A (generic over hash)
// ---------------------------------------------------------------------------

struct HmacDrbg {
    mode: Mode,
    key: Vec<u8>,
    v: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Mode {
    Sha1, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
    Sha3_224, Sha3_256, Sha3_384, Sha3_512,
}

impl HmacDrbg {
    fn new(mode_str: &str, entropy: &[u8], nonce: &[u8], perso: &[u8]) -> anyhow::Result<Self> {
        let mode = parse_mode(mode_str)?;
        let out_len = hash_out_len(mode);
        let key = vec![0u8; out_len];
        let v = vec![0x01u8; out_len];
        let mut drbg = Self { mode, key, v };
        let mut seed = Vec::with_capacity(entropy.len() + nonce.len() + perso.len());
        seed.extend_from_slice(entropy);
        seed.extend_from_slice(nonce);
        seed.extend_from_slice(perso);
        drbg.update(&seed);
        Ok(drbg)
    }

    fn update(&mut self, provided: &[u8]) {
        // K = HMAC(K, V || 0x00 || provided)
        let mut buf = self.v.clone();
        buf.push(0x00);
        buf.extend_from_slice(provided);
        self.key = hmac_with(self.mode, &self.key, &buf);
        // V = HMAC(K, V)
        self.v = hmac_with(self.mode, &self.key, &self.v);
        if provided.is_empty() {
            return;
        }
        // K = HMAC(K, V || 0x01 || provided)
        let mut buf2 = self.v.clone();
        buf2.push(0x01);
        buf2.extend_from_slice(provided);
        self.key = hmac_with(self.mode, &self.key, &buf2);
        self.v = hmac_with(self.mode, &self.key, &self.v);
    }

    fn reseed(&mut self, entropy: &[u8], addl: &[u8]) -> anyhow::Result<()> {
        let mut seed = Vec::with_capacity(entropy.len() + addl.len());
        seed.extend_from_slice(entropy);
        seed.extend_from_slice(addl);
        self.update(&seed);
        Ok(())
    }

    fn generate(&mut self, addl: &[u8], requested_bits: usize) -> anyhow::Result<Vec<u8>> {
        if !addl.is_empty() {
            self.update(addl);
        }
        let requested_bytes = (requested_bits + 7) / 8;
        let mut out = Vec::with_capacity(requested_bytes);
        while out.len() < requested_bytes {
            self.v = hmac_with(self.mode, &self.key, &self.v);
            out.extend_from_slice(&self.v);
        }
        out.truncate(requested_bytes);
        // Per spec, call update even if addl empty
        self.update(addl);
        Ok(out)
    }
}

fn parse_mode(s: &str) -> anyhow::Result<Mode> {
    Ok(match s {
        "SHA-1" => Mode::Sha1,
        "SHA2-224" => Mode::Sha224,
        "SHA2-256" => Mode::Sha256,
        "SHA2-384" => Mode::Sha384,
        "SHA2-512" => Mode::Sha512,
        "SHA2-512/224" => Mode::Sha512_224,
        "SHA2-512/256" => Mode::Sha512_256,
        "SHA3-224" => Mode::Sha3_224,
        "SHA3-256" => Mode::Sha3_256,
        "SHA3-384" => Mode::Sha3_384,
        "SHA3-512" => Mode::Sha3_512,
        _ => anyhow::bail!("unsupported hmacDRBG mode: {}", s),
    })
}

fn hash_out_len(mode: Mode) -> usize {
    match mode {
        Mode::Sha1 => 20,
        Mode::Sha224 | Mode::Sha512_224 | Mode::Sha3_224 => 28,
        Mode::Sha256 | Mode::Sha512_256 | Mode::Sha3_256 => 32,
        Mode::Sha384 | Mode::Sha3_384 => 48,
        Mode::Sha512 | Mode::Sha3_512 => 64,
    }
}

fn hmac_with(mode: Mode, key: &[u8], msg: &[u8]) -> Vec<u8> {
    macro_rules! do_hmac {
        ($t:ty) => {{
            let mut m = <Hmac<$t> as Mac>::new_from_slice(key).unwrap();
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match mode {
        Mode::Sha1 => do_hmac!(Sha1),
        Mode::Sha224 => do_hmac!(Sha224),
        Mode::Sha256 => do_hmac!(Sha256),
        Mode::Sha384 => do_hmac!(Sha384),
        Mode::Sha512 => do_hmac!(Sha512),
        Mode::Sha512_224 => do_hmac!(Sha512_224),
        Mode::Sha512_256 => do_hmac!(Sha512_256),
        Mode::Sha3_224 => do_hmac!(Sha3_224),
        Mode::Sha3_256 => do_hmac!(Sha3_256),
        Mode::Sha3_384 => do_hmac!(Sha3_384),
        Mode::Sha3_512 => do_hmac!(Sha3_512),
    }
}
