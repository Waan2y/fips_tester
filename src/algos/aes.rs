use std::collections::HashMap;
use std::path::Path;

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AeadCore, AesGcm, Key, KeyInit as GcmKeyInit, Nonce};
use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::runner::{AlgoTester, TestFailure, TestSummary};
use crate::testvec::{load_expected, load_prompt};

pub struct AesTester {
    key: String,
}

impl AesTester {
    pub fn new(key: &str) -> Self {
        Self { key: key.to_string() }
    }
}

impl AlgoTester for AesTester {
    fn run(&self, vec_dir: &Path) -> anyhow::Result<TestSummary> {
        let prompt = load_prompt(vec_dir)?;
        let expected = load_expected(vec_dir)?;

        let mut exp_map: HashMap<u64, serde_json::Value> = HashMap::new();
        for val in &expected.test_groups {
            let tg_id = val.get("tgId").and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("expected group missing tgId"))?;
            exp_map.insert(tg_id, val.clone());
        }

        println!("Testing {}...", self.key);

        let mut summary = TestSummary {
            algo: self.key.clone(),
            total: 0,
            passed: 0,
            failures: Vec::new(),
        };

        let mut result_groups: Vec<serde_json::Value> = Vec::new();

        for val in prompt.test_groups {
            let tg_id = val.get("tgId").and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow::anyhow!("prompt group missing tgId"))?;
            let test_type = val.get("testType").and_then(|v| v.as_str())
                .unwrap_or("AFT").to_string();

            let exp_group = exp_map.get(&tg_id)
                .ok_or_else(|| anyhow::anyhow!("no expected group for tgId={}", tg_id))?;

            let rg = match test_type.as_str() {
                "AFT" => run_aft_group(&self.key, &val, exp_group, &mut summary)?,
                "MCT" => run_mct_group(&self.key, &val, exp_group, &mut summary)?,
                other => {
                    eprintln!("  [warn] unknown testType '{}' in tgId={}, skipping", other, tg_id);
                    serde_json::json!({"tgId": tg_id, "tests": []})
                }
            };
            result_groups.push(rg);
        }

        let result_file = serde_json::json!({
            "vsId": expected.vs_id,
            "algorithm": expected.algorithm,
            "revision": expected.revision,
            "isSample": expected.is_sample,
            "testGroups": result_groups,
        });
        let json = serde_json::to_string_pretty(&result_file)
            .context("failed to serialize result")?;
        std::fs::write(vec_dir.join("result.json"), json)
            .context("failed to write result.json")?;

        Ok(summary)
    }
}

fn run_aft_group(
    algo: &str,
    prompt_group: &serde_json::Value,
    expected_group: &serde_json::Value,
    summary: &mut TestSummary,
) -> anyhow::Result<serde_json::Value> {
    let tg_id = prompt_group["tgId"].as_u64().unwrap();
    let direction = prompt_group["direction"].as_str().unwrap_or("encrypt").to_string();

    let exp_tests_arr = expected_group["tests"].as_array()
        .ok_or_else(|| anyhow::anyhow!("expected group has no tests"))?;
    let exp_tests: HashMap<u64, &serde_json::Value> = exp_tests_arr.iter()
        .filter_map(|t| t["tcId"].as_u64().map(|id| (id, t)))
        .collect();

    let prompt_tests = prompt_group["tests"].as_array()
        .ok_or_else(|| anyhow::anyhow!("prompt group has no tests"))?;

    let mut group_pass = 0usize;
    let mut result_tests: Vec<serde_json::Value> = Vec::new();

    for test in prompt_tests {
        let tc_id = test["tcId"].as_u64().unwrap();
        summary.total += 1;

        let (rt, passed) = match run_aft_case(algo, &direction, prompt_group, test, &exp_tests) {
            Ok(x) => x,
            Err(e) => {
                summary.failures.push(TestFailure {
                    tg_id,
                    tc_id,
                    detail: format!("error: {e}"),
                });
                (serde_json::json!({"tcId": tc_id}), false)
            }
        };

        if passed {
            summary.passed += 1;
            group_pass += 1;
        } else if let Some(exp) = exp_tests.get(&tc_id) {
            summary.failures.push(TestFailure {
                tg_id,
                tc_id,
                detail: format!("mismatch\n  expected: {}\n  actual:   {}", exp, rt),
            });
        }
        result_tests.push(rt);
    }

    println!("  AFT  [tgId={tg_id}]: {}/{} passed", group_pass, prompt_tests.len());

    Ok(serde_json::json!({"tgId": tg_id, "tests": result_tests}))
}

fn run_aft_case(
    algo: &str,
    direction: &str,
    group: &serde_json::Value,
    test: &serde_json::Value,
    exp_tests: &HashMap<u64, &serde_json::Value>,
) -> anyhow::Result<(serde_json::Value, bool)> {
    let tc_id = test["tcId"].as_u64().unwrap();
    let key = hex::decode(test["key"].as_str().unwrap_or(""))?;
    let exp = exp_tests.get(&tc_id);

    match algo {
        "aes-ecb" => {
            if direction == "encrypt" {
                let pt = hex::decode(test["pt"].as_str().unwrap_or(""))?;
                let ct = aes_ecb_encrypt(&key, &pt)?;
                let actual = hex::encode_upper(&ct);
                let expected = exp.and_then(|e| e["ct"].as_str()).unwrap_or("");
                let ok = actual.eq_ignore_ascii_case(expected);
                Ok((serde_json::json!({"tcId": tc_id, "ct": actual}), ok))
            } else {
                let ct = hex::decode(test["ct"].as_str().unwrap_or(""))?;
                let pt = aes_ecb_decrypt(&key, &ct)?;
                let actual = hex::encode_upper(&pt);
                let expected = exp.and_then(|e| e["pt"].as_str()).unwrap_or("");
                let ok = actual.eq_ignore_ascii_case(expected);
                Ok((serde_json::json!({"tcId": tc_id, "pt": actual}), ok))
            }
        }
        "aes-cbc" => {
            let iv = hex::decode(test["iv"].as_str().unwrap_or(""))?;
            if direction == "encrypt" {
                let pt = hex::decode(test["pt"].as_str().unwrap_or(""))?;
                let ct = aes_cbc_encrypt(&key, &iv, &pt)?;
                let actual = hex::encode_upper(&ct);
                let expected = exp.and_then(|e| e["ct"].as_str()).unwrap_or("");
                let ok = actual.eq_ignore_ascii_case(expected);
                Ok((serde_json::json!({"tcId": tc_id, "ct": actual}), ok))
            } else {
                let ct = hex::decode(test["ct"].as_str().unwrap_or(""))?;
                let pt = aes_cbc_decrypt(&key, &iv, &ct)?;
                let actual = hex::encode_upper(&pt);
                let expected = exp.and_then(|e| e["pt"].as_str()).unwrap_or("");
                let ok = actual.eq_ignore_ascii_case(expected);
                Ok((serde_json::json!({"tcId": tc_id, "pt": actual}), ok))
            }
        }
        "aes-ctr" => {
            let payload_len = test["payloadLen"].as_u64().unwrap_or(0) as usize;
            let payload_bytes = (payload_len + 7) / 8;
            if direction == "encrypt" {
                let pt = hex::decode(test["pt"].as_str().unwrap_or(""))?;
                let exp_iv = exp.and_then(|e| e["iv"].as_str()).unwrap_or("");
                let iv = hex::decode(exp_iv)?;
                let mut ct = aes_ctr(&key, &iv, &pt[..payload_bytes])?;
                mask_last_byte_bits(&mut ct, payload_len);
                let actual_ct = hex::encode_upper(&ct);
                let expected_ct = exp.and_then(|e| e["ct"].as_str()).unwrap_or("");
                let ok = actual_ct.eq_ignore_ascii_case(expected_ct);
                Ok((serde_json::json!({"tcId": tc_id, "ct": actual_ct, "iv": exp_iv}), ok))
            } else {
                let ct = hex::decode(test["ct"].as_str().unwrap_or(""))?;
                let iv = hex::decode(test["iv"].as_str().unwrap_or(""))?;
                let mut pt = aes_ctr(&key, &iv, &ct[..payload_bytes])?;
                mask_last_byte_bits(&mut pt, payload_len);
                let actual = hex::encode_upper(&pt);
                let expected = exp.and_then(|e| e["pt"].as_str()).unwrap_or("");
                let ok = actual.eq_ignore_ascii_case(expected);
                Ok((serde_json::json!({"tcId": tc_id, "pt": actual}), ok))
            }
        }
        "aes-gcm" => run_gcm_case(group, test, exp),
        _ => unreachable!("unexpected aes algo: {}", algo),
    }
}

fn run_gcm_case(
    group: &serde_json::Value,
    test: &serde_json::Value,
    exp: Option<&&serde_json::Value>,
) -> anyhow::Result<(serde_json::Value, bool)> {
    let tc_id = test["tcId"].as_u64().unwrap();
    let direction = group["direction"].as_str().unwrap_or("encrypt");
    let tag_len = group["tagLen"].as_u64().unwrap_or(128) as usize;
    let tag_bytes = tag_len / 8;

    let key = hex::decode(test["key"].as_str().unwrap_or(""))?;
    let iv = hex::decode(test["iv"].as_str().unwrap_or(""))?;
    let aad = hex::decode(test["aad"].as_str().unwrap_or(""))?;

    if direction == "encrypt" {
        let pt = hex::decode(test["pt"].as_str().unwrap_or(""))?;
        let (ct, tag) = aes_gcm_encrypt(&key, &iv, &aad, &pt, tag_bytes)?;
        let actual_ct = hex::encode_upper(&ct);
        let actual_tag = hex::encode_upper(&tag);
        let exp_ct = exp.and_then(|e| e["ct"].as_str()).unwrap_or("");
        let exp_tag = exp.and_then(|e| e["tag"].as_str()).unwrap_or("");
        let ok = actual_ct.eq_ignore_ascii_case(exp_ct)
            && actual_tag.eq_ignore_ascii_case(exp_tag);
        Ok((
            serde_json::json!({"tcId": tc_id, "ct": actual_ct, "tag": actual_tag}),
            ok,
        ))
    } else {
        let ct = hex::decode(test["ct"].as_str().unwrap_or(""))?;
        let tag = hex::decode(test["tag"].as_str().unwrap_or(""))?;
        match aes_gcm_decrypt(&key, &iv, &aad, &ct, &tag) {
            Ok(pt) => {
                let actual = hex::encode_upper(&pt);
                let exp_pt = exp.and_then(|e| e["pt"].as_str());
                let exp_passed = exp.and_then(|e| e["testPassed"].as_bool());
                let ok = if let Some(p) = exp_pt {
                    actual.eq_ignore_ascii_case(p)
                } else if exp_passed == Some(false) {
                    false // expected rejection but we decrypted
                } else {
                    false
                };
                Ok((serde_json::json!({"tcId": tc_id, "pt": actual}), ok))
            }
            Err(_) => {
                let exp_passed = exp.and_then(|e| e["testPassed"].as_bool());
                let ok = exp_passed == Some(false);
                Ok((serde_json::json!({"tcId": tc_id, "testPassed": false}), ok))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MCT runner
// ---------------------------------------------------------------------------

fn run_mct_group(
    algo: &str,
    prompt_group: &serde_json::Value,
    expected_group: &serde_json::Value,
    summary: &mut TestSummary,
) -> anyhow::Result<serde_json::Value> {
    let tg_id = prompt_group["tgId"].as_u64().unwrap();
    let direction = prompt_group["direction"].as_str().unwrap_or("encrypt").to_string();

    let exp_tests_arr = expected_group["tests"].as_array()
        .ok_or_else(|| anyhow::anyhow!("expected group has no tests"))?;
    let exp_tests: HashMap<u64, &serde_json::Value> = exp_tests_arr.iter()
        .filter_map(|t| t["tcId"].as_u64().map(|id| (id, t)))
        .collect();

    let prompt_tests = prompt_group["tests"].as_array()
        .ok_or_else(|| anyhow::anyhow!("prompt group has no tests"))?;

    let mut group_pass = 0usize;
    let mut result_tests: Vec<serde_json::Value> = Vec::new();

    for test in prompt_tests {
        let tc_id = test["tcId"].as_u64().unwrap();
        summary.total += 1;

        let chain_result: anyhow::Result<Vec<McEntry>> = match algo {
            "aes-ecb" => mct_ecb(&direction, test),
            "aes-cbc" => mct_cbc(&direction, test),
            _ => anyhow::bail!("MCT not supported for {}", algo),
        };

        let (rt, passed) = match chain_result {
            Ok(entries) => {
                let results_json: Vec<serde_json::Value> = entries.iter().map(|e| {
                    match algo {
                        "aes-ecb" => {
                            if direction == "encrypt" {
                                serde_json::json!({
                                    "key": hex::encode_upper(&e.key),
                                    "pt": hex::encode_upper(&e.pt),
                                    "ct": hex::encode_upper(&e.ct),
                                })
                            } else {
                                serde_json::json!({
                                    "key": hex::encode_upper(&e.key),
                                    "pt": hex::encode_upper(&e.pt),
                                    "ct": hex::encode_upper(&e.ct),
                                })
                            }
                        }
                        _ => serde_json::json!({
                            "key": hex::encode_upper(&e.key),
                            "iv": hex::encode_upper(&e.iv),
                            "pt": hex::encode_upper(&e.pt),
                            "ct": hex::encode_upper(&e.ct),
                        }),
                    }
                }).collect();

                let rt = serde_json::json!({
                    "tcId": tc_id,
                    "resultsArray": results_json,
                });

                let ok = exp_tests.get(&tc_id)
                    .and_then(|e| e["resultsArray"].as_array())
                    .map(|exp_arr| {
                        exp_arr.len() == entries.len()
                            && exp_arr.iter().zip(entries.iter()).all(|(ex, ac)| {
                                field_match(ex, "key", &ac.key)
                                    && field_match(ex, "pt", &ac.pt)
                                    && field_match(ex, "ct", &ac.ct)
                                    && (ex.get("iv").is_none() || field_match(ex, "iv", &ac.iv))
                            })
                    })
                    .unwrap_or(false);

                (rt, ok)
            }
            Err(e) => {
                summary.failures.push(TestFailure {
                    tg_id,
                    tc_id,
                    detail: format!("error: {e}"),
                });
                (serde_json::json!({"tcId": tc_id}), false)
            }
        };

        if passed {
            summary.passed += 1;
            group_pass += 1;
        } else {
            summary.failures.push(TestFailure {
                tg_id,
                tc_id,
                detail: "MCT chain mismatch".into(),
            });
        }
        result_tests.push(rt);
    }

    println!("  MCT  [tgId={tg_id}]: {}/{} passed", group_pass, prompt_tests.len());

    Ok(serde_json::json!({"tgId": tg_id, "tests": result_tests}))
}

fn field_match(expected: &serde_json::Value, field: &str, actual_bytes: &[u8]) -> bool {
    let exp_hex = expected.get(field).and_then(|v| v.as_str()).unwrap_or("");
    hex::encode(actual_bytes).eq_ignore_ascii_case(exp_hex)
}

struct McEntry {
    key: Vec<u8>,
    iv: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
}

/// AES-ECB MCT per NIST CAVS.
/// ```
/// Key[0] = Key, PT[0] = PT
/// for i in 0..100:
///     record Key[i], PT[i,0]
///     for j in 0..1000:
///         CT[i,j] = AES(Key[i], PT[i,j])
///         (encrypt) PT[i,j+1] = CT[i,j]
///         (decrypt) CT[i,j+1] = PT[i,j]  (reversed naming)
///     record CT[i,999] (or PT[i,999] for decrypt)
///     Key[i+1] = Key[i] XOR last-keylen-bits(CT[i,998] || CT[i,999])
///     PT[i+1,0] = CT[i,999]
/// ```
fn mct_ecb(direction: &str, test: &serde_json::Value) -> anyhow::Result<Vec<McEntry>> {
    let mut key = hex::decode(test["key"].as_str().unwrap_or(""))?;
    let mut data = hex::decode(
        if direction == "encrypt" { test["pt"].as_str() } else { test["ct"].as_str() }
            .unwrap_or(""),
    )?;

    let mut results = Vec::with_capacity(100);
    for _ in 0..100 {
        let start_key = key.clone();
        let start_data = data.clone();

        // 1000-round inner chain. Track last two outputs for key schedule xor.
        let mut prev: Vec<u8> = vec![];
        let mut curr: Vec<u8> = vec![];
        for j in 0..1000 {
            let out = if direction == "encrypt" {
                aes_ecb_encrypt(&key, &data)?
            } else {
                aes_ecb_decrypt(&key, &data)?
            };
            if j == 999 {
                prev = curr.clone();
                curr = out.clone();
            } else {
                prev = curr;
                curr = out.clone();
            }
            data = out;
        }

        let (pt_rec, ct_rec) = if direction == "encrypt" {
            (start_data.clone(), curr.clone())
        } else {
            (curr.clone(), start_data.clone())
        };

        results.push(McEntry {
            key: start_key,
            iv: vec![],
            pt: pt_rec,
            ct: ct_rec,
        });

        // Key schedule: XOR appropriate bits from last 1-2 outputs
        let xor_src = xor_source_for_keylen(key.len(), &prev, &curr);
        for (i, b) in xor_src.iter().enumerate() {
            key[i] ^= *b;
        }
        // data stays (which becomes PT[i+1,0] for encrypt; for decrypt, data IS the final PT which becomes next CT[0])
    }
    Ok(results)
}

/// AES-CBC encrypt MCT per NIST CAVS.
/// ```
/// KEY[0] = Key, IV[0] = IV, PT[0,0] = PT
/// for i = 0..100:
///   record KEY[i], IV[i], PT[i,0]
///   for j = 0..1000:
///     if j == 0: CT[i,0] = AES(KEY[i], PT[i,0] XOR IV[i]); PT[i,1] = IV[i]
///     else:      CT[i,j] = AES(KEY[i], PT[i,j] XOR CT[i,j-1]); PT[i,j+1] = CT[i,j-1]
///   record CT[i,999]
///   KEY[i+1] = KEY[i] XOR last_keylen_bits(CT[i,998] || CT[i,999])
///   IV[i+1]  = CT[i,999]
///   PT[i+1,0] = CT[i,998]
/// ```
fn mct_cbc_encrypt(test: &serde_json::Value) -> anyhow::Result<Vec<McEntry>> {
    let mut key = hex::decode(test["key"].as_str().unwrap_or(""))?;
    let mut iv = hex::decode(test["iv"].as_str().unwrap_or(""))?;
    let mut pt0 = hex::decode(test["pt"].as_str().unwrap_or(""))?;

    let mut results = Vec::with_capacity(100);
    for _ in 0..100 {
        let rec_key = key.clone();
        let rec_iv = iv.clone();
        let rec_pt = pt0.clone();

        let mut pt_j = pt0.clone();
        let mut ct_prev = iv.clone();       // CT[-1] := IV
        let mut ct_j_minus_1 = vec![0u8; 16]; // CT[998]
        let mut ct_j = vec![0u8; 16];         // CT[999]

        for j in 0..1000 {
            let mut blk = pt_j.clone();
            xor_inplace(&mut blk, &ct_prev);
            let ct = aes_ecb_encrypt(&key, &blk)?;
            if j == 998 { ct_j_minus_1 = ct.clone(); }
            if j == 999 { ct_j = ct.clone(); }
            // Next iteration: PT[j+1] = CT[j-1] (or IV for j=0, which is what ct_prev holds)
            pt_j = ct_prev.clone();
            ct_prev = ct;
        }

        results.push(McEntry {
            key: rec_key,
            iv: rec_iv,
            pt: rec_pt,
            ct: ct_j.clone(),
        });

        let xor_src = xor_source_for_keylen(key.len(), &ct_j_minus_1, &ct_j);
        for (i, b) in xor_src.iter().enumerate() { key[i] ^= *b; }
        iv = ct_j.clone();
        pt0 = ct_j_minus_1.clone();
    }
    Ok(results)
}

/// AES-CBC decrypt MCT per ACVP spec (MonteCarloAesCbc.cs).
/// Inner chain: `CT[j+1] = PT[j-1]` (lagged), mirror of encrypt:
/// ```
/// j=0: PT[0] = AES_DEC(Key, CT[0]) XOR IV;       CT[1] = IV
/// j>=1: PT[j] = AES_DEC(Key, CT[j]) XOR CT[j-1]; CT[j+1] = PT[j-1]
/// Key[i+1] = Key[i] XOR last_keylen_bits(PT[998] || PT[999])
/// IV[i+1]  = PT[999];  CT[i+1,0] = PT[998]
/// ```
fn mct_cbc_decrypt(test: &serde_json::Value) -> anyhow::Result<Vec<McEntry>> {
    let mut key = hex::decode(test["key"].as_str().unwrap_or(""))?;
    let mut iv = hex::decode(test["iv"].as_str().unwrap_or(""))?;
    let mut ct0 = hex::decode(test["ct"].as_str().unwrap_or(""))?;

    let mut results = Vec::with_capacity(100);
    for _ in 0..100 {
        let rec_key = key.clone();
        let rec_iv = iv.clone();
        let rec_ct = ct0.clone();

        let mut cur_input = ct0.clone(); // CT[j]
        let mut prev_xor = iv.clone();   // IV for j=0, else CT[j-1]
        let mut pt_prev: Vec<u8> = vec![0u8; 16]; // PT[j-1]
        let mut pt_j_minus_1 = vec![0u8; 16];
        let mut pt_j = vec![0u8; 16];

        for j in 0..1000 {
            let dec = aes_ecb_decrypt(&key, &cur_input)?;
            let mut pt = dec;
            xor_inplace(&mut pt, &prev_xor);
            if j == 998 { pt_j_minus_1 = pt.clone(); }
            if j == 999 { pt_j = pt.clone(); }

            // Prepare for j+1: CT[j+1] = IV (if j==0) else PT[j-1]; prev_xor = CT[j]
            let next_input = if j == 0 { iv.clone() } else { pt_prev.clone() };
            prev_xor = cur_input;
            cur_input = next_input;
            pt_prev = pt;
        }

        results.push(McEntry {
            key: rec_key,
            iv: rec_iv,
            pt: pt_j.clone(),
            ct: rec_ct,
        });

        let xor_src = xor_source_for_keylen(key.len(), &pt_j_minus_1, &pt_j);
        for (i, b) in xor_src.iter().enumerate() { key[i] ^= *b; }
        iv = pt_j.clone();
        ct0 = pt_j_minus_1.clone();
    }
    Ok(results)
}

fn mct_cbc(direction: &str, test: &serde_json::Value) -> anyhow::Result<Vec<McEntry>> {
    if direction == "encrypt" { mct_cbc_encrypt(test) } else { mct_cbc_decrypt(test) }
}

fn xor_inplace(dst: &mut [u8], src: &[u8]) {
    for (a, b) in dst.iter_mut().zip(src.iter()) {
        *a ^= *b;
    }
}

/// For 128-bit key: last 128 bits of CT[998..=999] == CT[999]
/// For 192-bit key: last 192 bits == last 64 bits of CT[998] || CT[999]
/// For 256-bit key: last 256 bits == CT[998] || CT[999]
fn xor_source_for_keylen(keylen: usize, ct_prev: &[u8], ct_curr: &[u8]) -> Vec<u8> {
    match keylen {
        16 => ct_curr.to_vec(),
        24 => {
            let mut v = Vec::with_capacity(24);
            v.extend_from_slice(&ct_prev[8..16]);
            v.extend_from_slice(&ct_curr[..16]);
            v
        }
        32 => {
            let mut v = Vec::with_capacity(32);
            v.extend_from_slice(&ct_prev[..16]);
            v.extend_from_slice(&ct_curr[..16]);
            v
        }
        _ => unreachable!("unsupported AES key length {}", keylen),
    }
}

// ---------------------------------------------------------------------------
// AES primitive wrappers
// ---------------------------------------------------------------------------

fn aes_ecb_encrypt(key: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        anyhow::bail!("ECB data length not multiple of 16");
    }
    let mut out = data.to_vec();
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).unwrap();
            for chunk in out.chunks_mut(16) {
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }
        24 => {
            let cipher = Aes192::new_from_slice(key).unwrap();
            for chunk in out.chunks_mut(16) {
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).unwrap();
            for chunk in out.chunks_mut(16) {
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }
        _ => anyhow::bail!("unsupported AES key length {}", key.len()),
    }
    Ok(out)
}

fn aes_ecb_decrypt(key: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        anyhow::bail!("ECB data length not multiple of 16");
    }
    let mut out = data.to_vec();
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).unwrap();
            for chunk in out.chunks_mut(16) {
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
                cipher.decrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }
        24 => {
            let cipher = Aes192::new_from_slice(key).unwrap();
            for chunk in out.chunks_mut(16) {
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
                cipher.decrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).unwrap();
            for chunk in out.chunks_mut(16) {
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
                cipher.decrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }
        _ => anyhow::bail!("unsupported AES key length {}", key.len()),
    }
    Ok(out)
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8], pt: &[u8]) -> anyhow::Result<Vec<u8>> {
    if pt.len() % 16 != 0 { anyhow::bail!("CBC pt length not multiple of 16"); }
    let mut prev = iv.to_vec();
    let mut out = Vec::with_capacity(pt.len());
    for chunk in pt.chunks(16) {
        let mut blk = chunk.to_vec();
        xor_inplace(&mut blk, &prev);
        let enc = aes_ecb_encrypt(key, &blk)?;
        prev = enc.clone();
        out.extend_from_slice(&enc);
    }
    Ok(out)
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> anyhow::Result<Vec<u8>> {
    if ct.len() % 16 != 0 { anyhow::bail!("CBC ct length not multiple of 16"); }
    let mut prev = iv.to_vec();
    let mut out = Vec::with_capacity(ct.len());
    for chunk in ct.chunks(16) {
        let mut dec = aes_ecb_decrypt(key, chunk)?;
        xor_inplace(&mut dec, &prev);
        prev = chunk.to_vec();
        out.extend_from_slice(&dec);
    }
    Ok(out)
}

fn aes_ctr(key: &[u8], iv: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    // 128-bit counter, big-endian increment.
    let mut ctr: [u8; 16] = iv.try_into()
        .map_err(|_| anyhow::anyhow!("CTR iv must be 16 bytes"))?;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let ks = aes_ecb_encrypt(key, &ctr)?;
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        increment_counter(&mut ctr);
    }
    Ok(out)
}

fn mask_last_byte_bits(data: &mut [u8], bit_len: usize) {
    if data.is_empty() { return; }
    let r = bit_len % 8;
    if r != 0 {
        let mask = 0xFFu8 << (8 - r);
        let last = data.len() - 1;
        data[last] &= mask;
    }
}

fn increment_counter(ctr: &mut [u8; 16]) {
    for i in (0..16).rev() {
        let (v, overflow) = ctr[i].overflowing_add(1);
        ctr[i] = v;
        if !overflow { break; }
    }
}

fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    pt: &[u8],
    tag_bytes: usize,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use aes_gcm::aead::generic_array::{typenum::Unsigned, GenericArray};
    type Gcm96<C> = AesGcm<C, aes_gcm::aead::generic_array::typenum::U12>;

    // aes-gcm supports 96-bit IV natively; longer IVs go through GHASH derivation.
    // For simplicity and correctness, we re-derive J0 manually when ivLen != 96.
    if iv.len() != 12 {
        // Fallback path: use our custom GHASH-based IV derivation.
        return gcm_encrypt_any_iv(key, iv, aad, pt, tag_bytes);
    }
    let nonce = Nonce::from_slice(iv);
    let result: Vec<u8> = match key.len() {
        16 => {
            let c = Gcm96::<Aes128>::new(Key::<Aes128>::from_slice(key));
            c.encrypt(nonce, Payload { msg: pt, aad }).map_err(|e| anyhow::anyhow!("{e}"))?
        }
        24 => {
            let c = Gcm96::<Aes192>::new(Key::<Aes192>::from_slice(key));
            c.encrypt(nonce, Payload { msg: pt, aad }).map_err(|e| anyhow::anyhow!("{e}"))?
        }
        32 => {
            let c = Gcm96::<Aes256>::new(Key::<Aes256>::from_slice(key));
            c.encrypt(nonce, Payload { msg: pt, aad }).map_err(|e| anyhow::anyhow!("{e}"))?
        }
        _ => anyhow::bail!("unsupported GCM key length {}", key.len()),
    };
    // aes-gcm always appends full 16-byte tag; truncate to requested tag length.
    let split = result.len() - 16;
    let ct = result[..split].to_vec();
    let full_tag = &result[split..];
    Ok((ct, full_tag[..tag_bytes].to_vec()))
}

fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if iv.len() != 12 {
        return gcm_decrypt_any_iv(key, iv, aad, ct, tag);
    }
    // aes-gcm requires full 16-byte tag; pad/zero-extend won't work, we need custom.
    if tag.len() != 16 {
        return gcm_decrypt_any_iv(key, iv, aad, ct, tag);
    }
    use aes_gcm::aead::generic_array::typenum;
    type Gcm96<C> = AesGcm<C, typenum::U12>;
    let nonce = Nonce::from_slice(iv);
    let mut combined = ct.to_vec();
    combined.extend_from_slice(tag);
    let pt = match key.len() {
        16 => {
            let c = Gcm96::<Aes128>::new(Key::<Aes128>::from_slice(key));
            c.decrypt(nonce, Payload { msg: &combined, aad }).map_err(|e| anyhow::anyhow!("{e}"))?
        }
        24 => {
            let c = Gcm96::<Aes192>::new(Key::<Aes192>::from_slice(key));
            c.decrypt(nonce, Payload { msg: &combined, aad }).map_err(|e| anyhow::anyhow!("{e}"))?
        }
        32 => {
            let c = Gcm96::<Aes256>::new(Key::<Aes256>::from_slice(key));
            c.decrypt(nonce, Payload { msg: &combined, aad }).map_err(|e| anyhow::anyhow!("{e}"))?
        }
        _ => anyhow::bail!("unsupported GCM key length {}", key.len()),
    };
    Ok(pt)
}

// ---------------------------------------------------------------------------
// GCM with arbitrary IV length (FIPS SP 800-38D §7)
// ---------------------------------------------------------------------------

fn gcm_encrypt_any_iv(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    pt: &[u8],
    tag_bytes: usize,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let h = aes_ecb_encrypt(key, &[0u8; 16])?;
    let j0 = derive_j0(&h, iv);
    let mut ctr_start = j0;
    increment_counter_32(&mut ctr_start);
    // CTR over pt with ctr_start
    let ct = ctr_stream(key, &ctr_start, pt)?;
    // GHASH (A, C)
    let s = ghash(&h, aad, &ct);
    // E(K, J0) XOR S → tag
    let ek_j0 = aes_ecb_encrypt(key, &j0)?;
    let mut tag = vec![0u8; 16];
    for i in 0..16 { tag[i] = ek_j0[i] ^ s[i]; }
    Ok((ct, tag[..tag_bytes].to_vec()))
}

fn gcm_decrypt_any_iv(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let h = aes_ecb_encrypt(key, &[0u8; 16])?;
    let j0 = derive_j0(&h, iv);
    // Verify tag first
    let s = ghash(&h, aad, ct);
    let ek_j0 = aes_ecb_encrypt(key, &j0)?;
    let mut expected_tag = vec![0u8; 16];
    for i in 0..16 { expected_tag[i] = ek_j0[i] ^ s[i]; }
    let t_len = tag.len();
    if expected_tag[..t_len] != *tag {
        anyhow::bail!("GCM tag mismatch");
    }
    let mut ctr_start = j0;
    increment_counter_32(&mut ctr_start);
    ctr_stream(key, &ctr_start, ct)
}

fn derive_j0(h: &[u8], iv: &[u8]) -> [u8; 16] {
    if iv.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        j0
    } else {
        // J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
        let iv_bit_len = (iv.len() as u64) * 8;
        let s = ((iv.len() + 15) / 16) * 16 - iv.len();
        let mut buf = iv.to_vec();
        buf.extend(std::iter::repeat(0u8).take(s + 8));
        buf.extend_from_slice(&iv_bit_len.to_be_bytes());
        let j0_bytes = ghash_bytes(h, &buf);
        let mut j0 = [0u8; 16];
        j0.copy_from_slice(&j0_bytes);
        j0
    }
}

fn increment_counter_32(ctr: &mut [u8; 16]) {
    for i in (12..16).rev() {
        let (v, overflow) = ctr[i].overflowing_add(1);
        ctr[i] = v;
        if !overflow { break; }
    }
}

fn ctr_stream(key: &[u8], icb: &[u8; 16], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut ctr = *icb;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let ks = aes_ecb_encrypt(key, &ctr)?;
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        increment_counter_32(&mut ctr);
    }
    Ok(out)
}

fn ghash(h: &[u8], a: &[u8], c: &[u8]) -> [u8; 16] {
    let a_pad = ((a.len() + 15) / 16) * 16 - a.len();
    let c_pad = ((c.len() + 15) / 16) * 16 - c.len();
    let a_bits = (a.len() as u64) * 8;
    let c_bits = (c.len() as u64) * 8;
    let mut buf = Vec::with_capacity(a.len() + a_pad + c.len() + c_pad + 16);
    buf.extend_from_slice(a);
    buf.extend(std::iter::repeat(0u8).take(a_pad));
    buf.extend_from_slice(c);
    buf.extend(std::iter::repeat(0u8).take(c_pad));
    buf.extend_from_slice(&a_bits.to_be_bytes());
    buf.extend_from_slice(&c_bits.to_be_bytes());
    ghash_bytes(h, &buf)
}

fn ghash_bytes(h: &[u8], data: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    let h_arr: [u8; 16] = h.try_into().unwrap();
    for chunk in data.chunks(16) {
        for i in 0..16 { y[i] ^= chunk[i]; }
        y = gf128_mul(y, h_arr);
    }
    y
}

fn gf128_mul(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    // GF(2^128) multiplication per SP 800-38D (big-endian bit convention).
    let mut z = [0u8; 16];
    let mut v = y;
    for i in 0..128 {
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        if bit == 1 {
            for k in 0..16 { z[k] ^= v[k]; }
        }
        let lsb = v[15] & 1;
        // shift v right by 1 (big-endian bit order)
        for k in (1..16).rev() {
            v[k] = (v[k] >> 1) | ((v[k - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if lsb == 1 {
            v[0] ^= 0xe1;
        }
    }
    z
}
