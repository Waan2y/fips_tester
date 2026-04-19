use std::path::Path;

use anyhow::Context as _;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use fips203::{ml_kem_1024, ml_kem_512, ml_kem_768};

use crate::runner::{AlgoTester, TestFailure, TestSummary};
use crate::testvec::{load_expected, load_prompt};

pub struct MlKemTester {
    key: String,
}

impl MlKemTester {
    pub fn new(key: &str) -> Self { Self { key: key.to_string() } }
}

impl AlgoTester for MlKemTester {
    fn run(&self, vec_dir: &Path) -> anyhow::Result<TestSummary> {
        let prompt = load_prompt(vec_dir)?;
        let expected = load_expected(vec_dir)?;

        println!("Testing {}...", self.key);

        let mut summary = TestSummary {
            algo: self.key.clone(),
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

        for g in &prompt.test_groups {
            let tg_id = g["tgId"].as_u64().unwrap_or(0);
            let eg = exp_groups.get(&tg_id).copied();
            let prompt_tests = g["tests"].as_array().cloned().unwrap_or_default();
            let exp_tests: std::collections::HashMap<u64, &serde_json::Value> = eg
                .and_then(|e| e["tests"].as_array())
                .map(|arr| arr.iter().filter_map(|t| t["tcId"].as_u64().map(|id| (id, t))).collect())
                .unwrap_or_default();

            let mut group_pass = 0usize;
            let mut result_tests: Vec<serde_json::Value> = Vec::new();

            for t in &prompt_tests {
                let tc_id = t["tcId"].as_u64().unwrap_or(0);
                summary.total += 1;
                let exp = exp_tests.get(&tc_id).copied();
                let (rt, passed) = match run_one(&self.key, g, t, exp) {
                    Ok(x) => x,
                    Err(e) => {
                        summary.failures.push(TestFailure {
                            tg_id, tc_id,
                            detail: format!("error: {e}"),
                        });
                        (serde_json::json!({"tcId": tc_id}), false)
                    }
                };
                if passed { summary.passed += 1; group_pass += 1; }
                else {
                    summary.failures.push(TestFailure {
                        tg_id, tc_id,
                        detail: "mismatch".into(),
                    });
                }
                result_tests.push(rt);
            }

            let param = g["parameterSet"].as_str().unwrap_or("?");
            let func = g["function"].as_str().unwrap_or("keygen");
            println!("  AFT  [tgId={tg_id} {param}/{func}]: {}/{} passed",
                     group_pass, prompt_tests.len());
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

enum ParamSet { K512, K768, K1024 }

fn parse_param(s: &str) -> anyhow::Result<ParamSet> {
    Ok(match s {
        "ML-KEM-512" => ParamSet::K512,
        "ML-KEM-768" => ParamSet::K768,
        "ML-KEM-1024" => ParamSet::K1024,
        _ => anyhow::bail!("unsupported ML-KEM param set: {s}"),
    })
}

fn run_one(
    algo: &str,
    group: &serde_json::Value,
    test: &serde_json::Value,
    exp: Option<&serde_json::Value>,
) -> anyhow::Result<(serde_json::Value, bool)> {
    let tc_id = test["tcId"].as_u64().unwrap_or(0);
    let param = parse_param(group["parameterSet"].as_str().unwrap_or(""))?;

    match algo {
        "ml-kem-keygen" => {
            let d = fixed_32(test["d"].as_str().unwrap_or(""))?;
            let z = fixed_32(test["z"].as_str().unwrap_or(""))?;
            let (ek, dk) = match param {
                ParamSet::K512 => {
                    let (ek, dk) = ml_kem_512::KG::keygen_from_seed(d, z);
                    (ek.into_bytes().to_vec(), dk.into_bytes().to_vec())
                }
                ParamSet::K768 => {
                    let (ek, dk) = ml_kem_768::KG::keygen_from_seed(d, z);
                    (ek.into_bytes().to_vec(), dk.into_bytes().to_vec())
                }
                ParamSet::K1024 => {
                    let (ek, dk) = ml_kem_1024::KG::keygen_from_seed(d, z);
                    (ek.into_bytes().to_vec(), dk.into_bytes().to_vec())
                }
            };
            let Some(e) = exp else { anyhow::bail!("keygen needs expected"); };
            let ek_exp = hex::decode(e["ek"].as_str().unwrap_or(""))?;
            let dk_exp = hex::decode(e["dk"].as_str().unwrap_or(""))?;
            let ok = ek == ek_exp && dk == dk_exp;
            Ok((
                serde_json::json!({"tcId": tc_id,
                    "ek": hex::encode_upper(&ek), "dk": hex::encode_upper(&dk)}),
                ok,
            ))
        }
        "ml-kem-encapdecap" => {
            let func = group["function"].as_str().unwrap_or("");
            match func {
                "encapsulation" => {
                    let ek_bytes = hex::decode(test["ek"].as_str().unwrap_or(""))?;
                    let m = fixed_32(test["m"].as_str().unwrap_or(""))?;
                    let (k, c) = match param {
                        ParamSet::K512 => {
                            let ek = ml_kem_512::EncapsKey::try_from_bytes(ek_bytes.clone().try_into().map_err(|_| anyhow::anyhow!("ek len"))?)
                                .map_err(|e| anyhow::anyhow!("ek parse: {e}"))?;
                            let (ss, ct) = ek.encaps_from_seed(&m);
                            (ss.into_bytes().to_vec(), ct.into_bytes().to_vec())
                        }
                        ParamSet::K768 => {
                            let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes.clone().try_into().map_err(|_| anyhow::anyhow!("ek len"))?)
                                .map_err(|e| anyhow::anyhow!("ek parse: {e}"))?;
                            let (ss, ct) = ek.encaps_from_seed(&m);
                            (ss.into_bytes().to_vec(), ct.into_bytes().to_vec())
                        }
                        ParamSet::K1024 => {
                            let ek = ml_kem_1024::EncapsKey::try_from_bytes(ek_bytes.clone().try_into().map_err(|_| anyhow::anyhow!("ek len"))?)
                                .map_err(|e| anyhow::anyhow!("ek parse: {e}"))?;
                            let (ss, ct) = ek.encaps_from_seed(&m);
                            (ss.into_bytes().to_vec(), ct.into_bytes().to_vec())
                        }
                    };
                    let Some(e) = exp else { anyhow::bail!("encaps needs expected"); };
                    let c_exp = hex::decode(e["c"].as_str().unwrap_or(""))?;
                    let k_exp = hex::decode(e["k"].as_str().unwrap_or(""))?;
                    let ok = c == c_exp && k == k_exp;
                    Ok((
                        serde_json::json!({"tcId": tc_id,
                            "c": hex::encode_upper(&c), "k": hex::encode_upper(&k)}),
                        ok,
                    ))
                }
                "decapsulation" => {
                    let dk_bytes = hex::decode(test["dk"].as_str().unwrap_or(""))?;
                    let c_bytes = hex::decode(test["c"].as_str().unwrap_or(""))?;
                    let k = match param {
                        ParamSet::K512 => {
                            let dk = ml_kem_512::DecapsKey::try_from_bytes(dk_bytes.clone().try_into().map_err(|_| anyhow::anyhow!("dk len"))?)
                                .map_err(|e| anyhow::anyhow!("dk parse: {e}"))?;
                            let ct = ml_kem_512::CipherText::try_from_bytes(c_bytes.clone().try_into().map_err(|_| anyhow::anyhow!("ct len"))?)
                                .map_err(|e| anyhow::anyhow!("ct parse: {e}"))?;
                            dk.try_decaps(&ct).map_err(|e| anyhow::anyhow!("decaps: {e}"))?
                                .into_bytes().to_vec()
                        }
                        ParamSet::K768 => {
                            let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes.clone().try_into().map_err(|_| anyhow::anyhow!("dk len"))?)
                                .map_err(|e| anyhow::anyhow!("dk parse: {e}"))?;
                            let ct = ml_kem_768::CipherText::try_from_bytes(c_bytes.clone().try_into().map_err(|_| anyhow::anyhow!("ct len"))?)
                                .map_err(|e| anyhow::anyhow!("ct parse: {e}"))?;
                            dk.try_decaps(&ct).map_err(|e| anyhow::anyhow!("decaps: {e}"))?
                                .into_bytes().to_vec()
                        }
                        ParamSet::K1024 => {
                            let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk_bytes.clone().try_into().map_err(|_| anyhow::anyhow!("dk len"))?)
                                .map_err(|e| anyhow::anyhow!("dk parse: {e}"))?;
                            let ct = ml_kem_1024::CipherText::try_from_bytes(c_bytes.clone().try_into().map_err(|_| anyhow::anyhow!("ct len"))?)
                                .map_err(|e| anyhow::anyhow!("ct parse: {e}"))?;
                            dk.try_decaps(&ct).map_err(|e| anyhow::anyhow!("decaps: {e}"))?
                                .into_bytes().to_vec()
                        }
                    };
                    let Some(e) = exp else { anyhow::bail!("decaps needs expected"); };
                    let k_exp = hex::decode(e["k"].as_str().unwrap_or(""))?;
                    let ok = k == k_exp;
                    Ok((
                        serde_json::json!({"tcId": tc_id, "k": hex::encode_upper(&k)}),
                        ok,
                    ))
                }
                "encapsulationKeyCheck" | "decapsulationKeyCheck" => {
                    // Structural: try to parse the key; if parse succeeds, key is valid.
                    let is_ek = func == "encapsulationKeyCheck";
                    let bytes = hex::decode(test[if is_ek { "ek" } else { "dk" }].as_str().unwrap_or(""))?;
                    let valid = match (&param, is_ek) {
                        (ParamSet::K512, true) => ml_kem_512::EncapsKey::try_from_bytes(bytes.clone().try_into().map_err(|_| ()).unwrap_or([0u8; ml_kem_512::EK_LEN])).is_ok() && bytes.len() == ml_kem_512::EK_LEN,
                        (ParamSet::K768, true) => ml_kem_768::EncapsKey::try_from_bytes(bytes.clone().try_into().map_err(|_| ()).unwrap_or([0u8; ml_kem_768::EK_LEN])).is_ok() && bytes.len() == ml_kem_768::EK_LEN,
                        (ParamSet::K1024, true) => ml_kem_1024::EncapsKey::try_from_bytes(bytes.clone().try_into().map_err(|_| ()).unwrap_or([0u8; ml_kem_1024::EK_LEN])).is_ok() && bytes.len() == ml_kem_1024::EK_LEN,
                        (ParamSet::K512, false) => ml_kem_512::DecapsKey::try_from_bytes(bytes.clone().try_into().map_err(|_| ()).unwrap_or([0u8; ml_kem_512::DK_LEN])).is_ok() && bytes.len() == ml_kem_512::DK_LEN,
                        (ParamSet::K768, false) => ml_kem_768::DecapsKey::try_from_bytes(bytes.clone().try_into().map_err(|_| ()).unwrap_or([0u8; ml_kem_768::DK_LEN])).is_ok() && bytes.len() == ml_kem_768::DK_LEN,
                        (ParamSet::K1024, false) => ml_kem_1024::DecapsKey::try_from_bytes(bytes.clone().try_into().map_err(|_| ()).unwrap_or([0u8; ml_kem_1024::DK_LEN])).is_ok() && bytes.len() == ml_kem_1024::DK_LEN,
                    };
                    let expected_passed = exp.and_then(|e| e["testPassed"].as_bool()).unwrap_or(false);
                    Ok((
                        serde_json::json!({"tcId": tc_id, "testPassed": valid}),
                        valid == expected_passed,
                    ))
                }
                other => anyhow::bail!("unknown ML-KEM function: {other}"),
            }
        }
        _ => unreachable!(),
    }
}

fn fixed_32(hex: &str) -> anyhow::Result<[u8; 32]> {
    let b = ::hex::decode(hex)?;
    b.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}
