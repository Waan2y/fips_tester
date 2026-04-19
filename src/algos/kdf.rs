use std::path::Path;

use aes::{Aes128, Aes192, Aes256};
use anyhow::Context as _;
use cmac::{Cmac, Mac as CmacMac};
use des::TdesEde3;
use hmac::{Hmac, Mac as HmacMac};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

use crate::runner::{AlgoTester, TestFailure, TestSummary};
use crate::testvec::{load_expected, load_prompt};

pub struct KdfTester;

impl KdfTester {
    pub fn new() -> Self { Self }
}

impl AlgoTester for KdfTester {
    fn run(&self, vec_dir: &Path) -> anyhow::Result<TestSummary> {
        let prompt = load_prompt(vec_dir)?;
        let expected = load_expected(vec_dir)?;

        println!("Testing kdf...");

        let mut summary = TestSummary {
            algo: "kdf".to_string(),
            total: 0,
            passed: 0,
            failures: Vec::new(),
        };

        let mut exp_groups: std::collections::HashMap<u64, &serde_json::Value> =
            std::collections::HashMap::new();
        for g in &expected.test_groups {
            let tg_id = g["tgId"].as_u64().unwrap_or(0);
            exp_groups.insert(tg_id, g);
        }

        let mut result_groups: Vec<serde_json::Value> = Vec::new();
        let mut silent = true;
        let total_groups = prompt.test_groups.len();

        for (gi, g) in prompt.test_groups.iter().enumerate() {
            let tg_id = g["tgId"].as_u64().unwrap_or(0);
            let mac_mode = g["macMode"].as_str().unwrap_or("").to_string();
            let kdf_mode = g["kdfMode"].as_str().unwrap_or("").to_string();
            let counter_location = g["counterLocation"].as_str().unwrap_or("").to_string();
            let counter_length = g["counterLength"].as_u64().unwrap_or(0) as usize;
            let key_out_length = g["keyOutLength"].as_u64().unwrap_or(0) as usize;
            let eg = exp_groups.get(&tg_id).copied();

            let prompt_tests = g["tests"].as_array().cloned().unwrap_or_default();
            let exp_tests: std::collections::HashMap<u64, &serde_json::Value> = eg
                .and_then(|e| e["tests"].as_array())
                .map(|arr| {
                    arr.iter().filter_map(|t| t["tcId"].as_u64().map(|id| (id, t))).collect()
                })
                .unwrap_or_default();

            let mut group_pass = 0usize;
            let total_in_group = prompt_tests.len();
            let mut result_tests: Vec<serde_json::Value> = Vec::new();

            for t in &prompt_tests {
                let tc_id = t["tcId"].as_u64().unwrap_or(0);
                summary.total += 1;

                let exp = exp_tests.get(&tc_id).copied();
                let fixed_data_hex = exp.and_then(|e| e["fixedData"].as_str()).unwrap_or("");
                let expected_key_out = exp.and_then(|e| e["keyOut"].as_str()).unwrap_or("").to_string();

                let break_location = exp.and_then(|e| e["breakLocation"].as_u64())
                    .map(|v| v as usize);

                let result = (|| -> anyhow::Result<Vec<u8>> {
                    let key_in = hex::decode(t["keyIn"].as_str().unwrap_or(""))?;
                    let fixed_data = hex::decode(fixed_data_hex)?;
                    let iv_hex = t["iv"].as_str().unwrap_or("");
                    let iv = if iv_hex.is_empty() { Vec::new() } else { hex::decode(iv_hex)? };

                    derive_kdf(
                        &kdf_mode,
                        &mac_mode,
                        &counter_location,
                        counter_length,
                        key_out_length,
                        &key_in,
                        &fixed_data,
                        &iv,
                        break_location,
                    )
                })();

                match result {
                    Ok(out) => {
                        let actual = hex::encode_upper(&out);
                        result_tests.push(serde_json::json!({
                            "tcId": tc_id,
                            "fixedData": fixed_data_hex,
                            "keyOut": actual.clone(),
                        }));
                        if actual.eq_ignore_ascii_case(&expected_key_out) {
                            summary.passed += 1;
                            group_pass += 1;
                        } else {
                            summary.failures.push(TestFailure {
                                tg_id, tc_id,
                                detail: "keyOut mismatch".into(),
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

            if gi < 3 || gi == total_groups - 1 || group_pass < total_in_group {
                silent = false;
                println!(
                    "  AFT  [tgId={tg_id} {}/{} {}+{}]: {}/{} passed",
                    kdf_mode, mac_mode, counter_location, counter_length,
                    group_pass, total_in_group
                );
            }
            result_groups.push(serde_json::json!({"tgId": tg_id, "tests": result_tests}));
        }

        if silent {
            println!("  (all {} groups silent-passed)", total_groups);
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
// KDF core (SP 800-108)
// ---------------------------------------------------------------------------

fn derive_kdf(
    kdf_mode: &str,
    mac_mode: &str,
    counter_location: &str,
    counter_length: usize,
    key_out_length_bits: usize,
    key_in: &[u8],
    fixed_data: &[u8],
    iv: &[u8],
    break_location: Option<usize>,
) -> anyhow::Result<Vec<u8>> {
    let out_bytes = (key_out_length_bits + 7) / 8;
    let mac_out_len = mac_output_len(mac_mode);
    let n = (out_bytes + mac_out_len - 1) / mac_out_len;

    // SP 800-108 allows counter_length == 0 for non-counter variants with no counter ("none" location).
    let mut out = Vec::with_capacity(n * mac_out_len);

    match kdf_mode {
        "counter" => {
            for i in 1..=n {
                let ctr = encode_counter(i as u64, counter_length);
                let msg = build_counter_message(&ctr, counter_location, fixed_data, break_location);
                let block = mac_run(mac_mode, key_in, &msg)?;
                out.extend_from_slice(&block);
            }
        }
        "feedback" => {
            let mut prev = iv.to_vec();
            for i in 1..=n {
                let ctr = encode_counter(i as u64, counter_length);
                let msg = build_feedback_message(&prev, &ctr, counter_location, fixed_data);
                let block = mac_run(mac_mode, key_in, &msg)?;
                prev = block.clone();
                out.extend_from_slice(&block);
            }
        }
        "double pipeline iteration" => {
            let mut a = fixed_data.to_vec();
            for i in 1..=n {
                a = mac_run(mac_mode, key_in, &a)?;
                let ctr = encode_counter(i as u64, counter_length);
                let msg = build_feedback_message(&a, &ctr, counter_location, fixed_data);
                let block = mac_run(mac_mode, key_in, &msg)?;
                out.extend_from_slice(&block);
            }
        }
        other => anyhow::bail!("unsupported KDF mode: {other}"),
    }

    out.truncate(out_bytes);
    // Mask partial byte if key_out_length not byte-aligned.
    let r = key_out_length_bits % 8;
    if r != 0 && !out.is_empty() {
        let last = out.len() - 1;
        out[last] &= 0xFFu8 << (8 - r);
    }
    Ok(out)
}

fn encode_counter(i: u64, counter_length_bits: usize) -> Vec<u8> {
    let bytes = counter_length_bits / 8;
    if bytes == 0 { return Vec::new(); }
    let mut v = Vec::with_capacity(bytes);
    for k in (0..bytes).rev() {
        v.push(((i >> (8 * k)) & 0xff) as u8);
    }
    v
}

fn build_counter_message(
    ctr: &[u8],
    location: &str,
    fixed_data: &[u8],
    break_location: Option<usize>,
) -> Vec<u8> {
    match location {
        "before fixed data" => {
            let mut m = Vec::with_capacity(ctr.len() + fixed_data.len());
            m.extend_from_slice(ctr);
            m.extend_from_slice(fixed_data);
            m
        }
        "after fixed data" => {
            let mut m = Vec::with_capacity(ctr.len() + fixed_data.len());
            m.extend_from_slice(fixed_data);
            m.extend_from_slice(ctr);
            m
        }
        "middle fixed data" => {
            // ACVP provides breakLocation (in bits) where counter is spliced into fixed_data.
            let brk = break_location.unwrap_or(fixed_data.len() * 4); // fallback midpoint
            splice_bits(fixed_data, brk, ctr)
        }
        "none" => fixed_data.to_vec(),
        _ => fixed_data.to_vec(),
    }
}

/// Splice `middle` bytes into `data` at bit position `at_bits`.
/// Result bit-string = data[0..at_bits] || middle || data[at_bits..end].
/// MSB-first bit ordering; packs back to bytes with zero padding on the last byte.
fn splice_bits(data: &[u8], at_bits: usize, middle: &[u8]) -> Vec<u8> {
    let first_bits = at_bits;
    let last_bits = data.len() * 8 - at_bits;
    let middle_bits = middle.len() * 8;
    let total_bits = first_bits + middle_bits + last_bits;
    let total_bytes = (total_bits + 7) / 8;
    let mut out = vec![0u8; total_bytes];

    let mut pos = 0usize; // bit position in out
    // First slice of fixed_data
    copy_bits(&mut out, &mut pos, data, 0, first_bits);
    // Middle (counter)
    copy_bits(&mut out, &mut pos, middle, 0, middle_bits);
    // Last slice of fixed_data
    copy_bits(&mut out, &mut pos, data, first_bits, last_bits);

    out
}

fn copy_bits(dst: &mut [u8], dst_pos: &mut usize, src: &[u8], src_start: usize, nbits: usize) {
    for i in 0..nbits {
        let sb = src_start + i;
        let bit = (src[sb / 8] >> (7 - (sb % 8))) & 1;
        if bit != 0 {
            let db = *dst_pos;
            dst[db / 8] |= 1 << (7 - (db % 8));
        }
        *dst_pos += 1;
    }
}

fn build_feedback_message(prev: &[u8], ctr: &[u8], location: &str, fixed_data: &[u8]) -> Vec<u8> {
    // Per ACVP-Server FeedbackKdf.cs / PipelineKdf.cs — `prev` is K(i-1) (feedback) or A(i) (double pipeline).
    match location {
        "before iterator" => {
            // counter || prev || fixed_data
            let mut m = Vec::new();
            m.extend_from_slice(ctr);
            m.extend_from_slice(prev);
            m.extend_from_slice(fixed_data);
            m
        }
        "after fixed data" => {
            // prev || fixed_data || counter
            let mut m = Vec::new();
            m.extend_from_slice(prev);
            m.extend_from_slice(fixed_data);
            m.extend_from_slice(ctr);
            m
        }
        "before fixed data" => {
            // prev || counter || fixed_data
            let mut m = Vec::new();
            m.extend_from_slice(prev);
            m.extend_from_slice(ctr);
            m.extend_from_slice(fixed_data);
            m
        }
        "none" => {
            let mut m = Vec::new();
            m.extend_from_slice(prev);
            m.extend_from_slice(fixed_data);
            m
        }
        _ => {
            let mut m = Vec::new();
            m.extend_from_slice(prev);
            m.extend_from_slice(ctr);
            m.extend_from_slice(fixed_data);
            m
        }
    }
}

// ---------------------------------------------------------------------------
// MAC dispatcher
// ---------------------------------------------------------------------------

fn mac_output_len(mac: &str) -> usize {
    match mac {
        "CMAC-AES128" | "CMAC-AES192" | "CMAC-AES256" => 16,
        "CMAC-TDES" => 8,
        "HMAC-SHA-1" => 20,
        "HMAC-SHA2-224" | "HMAC-SHA2-512/224" | "HMAC-SHA3-224" => 28,
        "HMAC-SHA2-256" | "HMAC-SHA2-512/256" | "HMAC-SHA3-256" => 32,
        "HMAC-SHA2-384" | "HMAC-SHA3-384" => 48,
        "HMAC-SHA2-512" | "HMAC-SHA3-512" => 64,
        _ => 0,
    }
}

fn mac_run(mac: &str, key: &[u8], msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    macro_rules! hmac_do {
        ($t:ty) => {{
            let mut m = <Hmac<$t> as HmacMac>::new_from_slice(key).unwrap();
            m.update(msg);
            Ok(m.finalize().into_bytes().to_vec())
        }};
    }
    match mac {
        "CMAC-AES128" => {
            let mut m = <Cmac<Aes128> as CmacMac>::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("cmac-aes128 key: {e}"))?;
            m.update(msg);
            Ok(m.finalize().into_bytes().to_vec())
        }
        "CMAC-AES192" => {
            let mut m = <Cmac<Aes192> as CmacMac>::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("cmac-aes192 key: {e}"))?;
            m.update(msg);
            Ok(m.finalize().into_bytes().to_vec())
        }
        "CMAC-AES256" => {
            let mut m = <Cmac<Aes256> as CmacMac>::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("cmac-aes256 key: {e}"))?;
            m.update(msg);
            Ok(m.finalize().into_bytes().to_vec())
        }
        "CMAC-TDES" => {
            let mut m = <Cmac<TdesEde3> as CmacMac>::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("cmac-tdes key: {e}"))?;
            m.update(msg);
            Ok(m.finalize().into_bytes().to_vec())
        }
        "HMAC-SHA-1" => hmac_do!(Sha1),
        "HMAC-SHA2-224" => hmac_do!(Sha224),
        "HMAC-SHA2-256" => hmac_do!(Sha256),
        "HMAC-SHA2-384" => hmac_do!(Sha384),
        "HMAC-SHA2-512" => hmac_do!(Sha512),
        "HMAC-SHA2-512/224" => hmac_do!(Sha512_224),
        "HMAC-SHA2-512/256" => hmac_do!(Sha512_256),
        "HMAC-SHA3-224" => hmac_do!(Sha3_224),
        "HMAC-SHA3-256" => hmac_do!(Sha3_256),
        "HMAC-SHA3-384" => hmac_do!(Sha3_384),
        "HMAC-SHA3-512" => hmac_do!(Sha3_512),
        other => anyhow::bail!("unsupported MAC: {other}"),
    }
}
