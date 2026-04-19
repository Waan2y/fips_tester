use std::collections::HashMap;
use std::path::Path;

use anyhow::Context as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

use crate::runner::{AlgoTester, TestFailure, TestSummary};
use crate::testvec::{load_expected, load_prompt};

pub struct HmacTester {
    key: String,
}

impl HmacTester {
    pub fn new(key: &str) -> Self {
        Self { key: key.to_string() }
    }
}

impl AlgoTester for HmacTester {
    fn run(&self, vec_dir: &Path) -> anyhow::Result<TestSummary> {
        let prompt = load_prompt(vec_dir)?;
        let expected = load_expected(vec_dir)?;

        let mut exp_map: HashMap<u64, ExpGroup> = HashMap::new();
        for val in &expected.test_groups {
            let g: ExpGroup = serde_json::from_value(val.clone())
                .context("failed to parse expected HMAC group")?;
            exp_map.insert(g.tg_id, g);
        }

        println!("Testing {}...", self.key);

        let mut summary = TestSummary {
            algo: self.key.clone(),
            total: 0,
            passed: 0,
            failures: Vec::new(),
        };

        let mut result_groups: Vec<ResultGroup> = Vec::new();

        for val in prompt.test_groups {
            let pg: PromptGroup = serde_json::from_value(val)
                .context("failed to parse prompt HMAC group")?;

            let eg = exp_map
                .get(&pg.tg_id)
                .ok_or_else(|| anyhow::anyhow!("no expected group for tgId={}", pg.tg_id))?;
            let exp_tests: HashMap<u64, &ExpTest> =
                eg.tests.iter().map(|t| (t.tc_id, t)).collect();

            let rg = run_aft(&self.key, &pg, &exp_tests, &mut summary);
            result_groups.push(rg);
        }

        let result_file = ResultFile {
            vs_id: expected.vs_id,
            algorithm: expected.algorithm,
            revision: expected.revision,
            is_sample: expected.is_sample,
            test_groups: result_groups,
        };
        let json = serde_json::to_string_pretty(&result_file)
            .context("failed to serialize result")?;
        std::fs::write(vec_dir.join("result.json"), json)
            .context("failed to write result.json")?;

        Ok(summary)
    }
}

fn run_aft(
    key: &str,
    pg: &PromptGroup,
    expected: &HashMap<u64, &ExpTest>,
    summary: &mut TestSummary,
) -> ResultGroup {
    let mut group_pass = 0usize;
    let mut result_tests: Vec<ResultTest> = Vec::new();

    for test in &pg.tests {
        summary.total += 1;

        let result = (|| -> anyhow::Result<Vec<u8>> {
            let k = hex::decode(&test.key)
                .map_err(|e| anyhow::anyhow!("key hex decode: {e}"))?;
            let msg = if test.msg.is_empty() {
                Vec::new()
            } else {
                hex::decode(&test.msg)
                    .map_err(|e| anyhow::anyhow!("msg hex decode: {e}"))?
            };
            let mac_bytes = (test.mac_len as usize + 7) / 8;
            Ok(hmac_mac(key, &k, &msg, mac_bytes))
        })();

        match result {
            Ok(actual) => {
                let actual_hex = hex::encode_upper(&actual);
                result_tests.push(ResultTest {
                    tc_id: test.tc_id,
                    mac: Some(actual_hex.clone()),
                });

                let exp_mac = expected
                    .get(&test.tc_id)
                    .map(|e| e.mac.as_str())
                    .unwrap_or("");
                if actual_hex.eq_ignore_ascii_case(exp_mac) {
                    summary.passed += 1;
                    group_pass += 1;
                } else {
                    summary.failures.push(TestFailure {
                        tg_id: pg.tg_id,
                        tc_id: test.tc_id,
                        detail: format!(
                            "expected: {}\n  actual: {}",
                            exp_mac.to_ascii_lowercase(),
                            actual_hex.to_ascii_lowercase()
                        ),
                    });
                }
            }
            Err(e) => {
                result_tests.push(ResultTest {
                    tc_id: test.tc_id,
                    mac: None,
                });
                summary.failures.push(TestFailure {
                    tg_id: pg.tg_id,
                    tc_id: test.tc_id,
                    detail: format!("error: {e}"),
                });
            }
        }
    }

    println!(
        "  AFT  [tgId={}]: {}/{} passed",
        pg.tg_id,
        group_pass,
        pg.tests.len()
    );

    ResultGroup {
        tg_id: pg.tg_id,
        tests: result_tests,
    }
}

fn hmac_mac(algo: &str, key: &[u8], msg: &[u8], out_bytes: usize) -> Vec<u8> {
    let full: Vec<u8> = match algo {
        "hmac-sha2-256" => {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        "hmac-sha2-384" => {
            let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).unwrap();
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        "hmac-sha2-512" => {
            let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key).unwrap();
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        "hmac-sha3-256" => {
            let mut m = <Hmac<Sha3_256> as Mac>::new_from_slice(key).unwrap();
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        "hmac-sha3-384" => {
            let mut m = <Hmac<Sha3_384> as Mac>::new_from_slice(key).unwrap();
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        "hmac-sha3-512" => {
            let mut m = <Hmac<Sha3_512> as Mac>::new_from_slice(key).unwrap();
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        _ => unreachable!("unexpected hmac key: {}", algo),
    };
    let take = out_bytes.min(full.len());
    full[..take].to_vec()
}

#[derive(Serialize)]
struct ResultFile {
    #[serde(rename = "vsId")]
    vs_id: u64,
    algorithm: String,
    revision: String,
    #[serde(rename = "isSample")]
    is_sample: bool,
    #[serde(rename = "testGroups")]
    test_groups: Vec<ResultGroup>,
}

#[derive(Serialize)]
struct ResultGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    tests: Vec<ResultTest>,
}

#[derive(Serialize)]
struct ResultTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
}

#[derive(Deserialize)]
struct PromptGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    tests: Vec<PromptTest>,
}

#[derive(Deserialize)]
struct PromptTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    key: String,
    #[serde(default)]
    msg: String,
    #[serde(rename = "macLen")]
    mac_len: u64,
}

#[derive(Deserialize)]
struct ExpGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    tests: Vec<ExpTest>,
}

#[derive(Deserialize)]
struct ExpTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    mac: String,
}
