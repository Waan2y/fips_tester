use std::collections::HashMap;
use std::path::Path;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};
use sha3::digest::{ExtendableOutput, Update as XofUpdate, XofReader};

use crate::runner::{AlgoTester, TestFailure, TestSummary};
use keccak;
use crate::testvec::{load_expected, load_prompt};

// ---------------------------------------------------------------------------
// Public tester
// ---------------------------------------------------------------------------

pub struct ShaTester {
    key: String,
}

impl ShaTester {
    pub fn new(key: &str) -> Self {
        Self { key: key.to_string() }
    }
}

impl AlgoTester for ShaTester {
    fn run(&self, vec_dir: &Path) -> anyhow::Result<TestSummary> {
        let prompt = load_prompt(vec_dir)?;
        let expected = load_expected(vec_dir)?;

        // Index expected groups by tgId for O(1) lookup.
        let mut exp_map: HashMap<u64, ShaExpectedGroup> = HashMap::new();
        for val in &expected.test_groups {
            let g: ShaExpectedGroup = serde_json::from_value(val.clone())
                .context("failed to parse expected group")?;
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
            let pg: ShaPromptGroup = serde_json::from_value(val)
                .context("failed to parse prompt group")?;

            let eg = exp_map
                .get(&pg.tg_id)
                .ok_or_else(|| anyhow::anyhow!("no expected group for tgId={}", pg.tg_id))?;

            let exp_tests: HashMap<u64, &ShaExpectedTest> =
                eg.tests.iter().map(|t| (t.tc_id, t)).collect();

            let rg = match pg.test_type.as_str() {
                "AFT" => run_aft(&self.key, pg.tg_id, &pg.tests, &exp_tests, &mut summary),
                "MCT" => run_mct(&self.key, pg.tg_id, &pg.tests, &exp_tests, &mut summary),
                "LDT" => {
                    println!("  LDT  [tgId={}]: skipped", pg.tg_id);
                    continue; // result.json에 포함하지 않음
                }
                other => {
                    eprintln!("  [warn] unknown testType '{}' in tgId={}, skipping", other, pg.tg_id);
                    ResultGroup { tg_id: pg.tg_id, tests: vec![] }
                }
            };
            result_groups.push(rg);
        }

        // result.json 저장 (expectedResult.json 과 동일한 형식)
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

// ---------------------------------------------------------------------------
// Result output types (expectedResult.json 과 동일한 형식)
// ---------------------------------------------------------------------------

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
    md: Option<String>,
    #[serde(rename = "resultsArray", skip_serializing_if = "Option::is_none")]
    results_array: Option<Vec<ResultMctEntry>>,
}

#[derive(Serialize)]
struct ResultMctEntry {
    md: String,
}

// ---------------------------------------------------------------------------
// Internal serde types (scoped to this module)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ShaPromptGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    #[serde(rename = "testType")]
    test_type: String,
    tests: Vec<ShaPromptTest>,
}

#[derive(Deserialize)]
struct ShaPromptTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    msg: Option<String>,
    len: Option<u64>,
    /// SHAKE AFT: output length in bits
    #[serde(rename = "outLen")]
    out_len: Option<u64>,
    /// LDT: large message descriptor
    #[serde(rename = "largeMsg")]
    #[allow(dead_code)]
    large_msg: Option<LargeMsg>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct LargeMsg {
    content: String,
    #[serde(rename = "contentLength")]
    content_length: u64,
    #[serde(rename = "fullLength")]
    full_length: u64,
    #[serde(rename = "expansionTechnique")]
    expansion_technique: String,
}

#[derive(Deserialize)]
struct ShaExpectedGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    tests: Vec<ShaExpectedTest>,
}

#[derive(Deserialize)]
struct ShaExpectedTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    /// AFT / LDT result
    md: Option<String>,
    /// MCT results — 100 entries
    #[serde(rename = "resultsArray")]
    results_array: Option<Vec<MctEntry>>,
}

#[derive(Deserialize)]
struct MctEntry {
    md: String,
}

// ---------------------------------------------------------------------------
// Test type runners
// ---------------------------------------------------------------------------

fn run_aft(
    key: &str,
    tg_id: u64,
    tests: &[ShaPromptTest],
    expected: &HashMap<u64, &ShaExpectedTest>,
    summary: &mut TestSummary,
) -> ResultGroup {
    let mut group_pass = 0usize;
    let mut result_tests: Vec<ResultTest> = Vec::new();

    for test in tests {
        summary.total += 1;

        let result = (|| -> anyhow::Result<Vec<u8>> {
            let msg = decode_msg(test.msg.as_deref(), test.len)?;
            let len_bits = test.len.unwrap_or(0) as usize;
            let actual = if is_shake(key) {
                let out_bits = test
                    .out_len
                    .ok_or_else(|| anyhow::anyhow!("outLen missing for SHAKE AFT"))? as usize;
                shake_xof(key, &msg, out_bits)
            } else if is_sha3(key) {
                sha3_hash_bits(key, &msg, len_bits)
            } else if len_bits % 8 != 0 {
                sha2_hash_bits(key, &msg, len_bits)
            } else {
                sha_hash(key, &msg)
            };
            Ok(actual)
        })();

        match result {
            Ok(actual) => {
                let actual_hex = hex::encode_upper(&actual);
                result_tests.push(ResultTest {
                    tc_id: test.tc_id,
                    md: Some(actual_hex.clone()),
                    results_array: None,
                });

                let exp_md = expected
                    .get(&test.tc_id)
                    .and_then(|e| e.md.as_deref())
                    .unwrap_or("");
                if hex_eq(&actual, exp_md) {
                    summary.passed += 1;
                    group_pass += 1;
                } else {
                    summary.failures.push(TestFailure {
                        tg_id,
                        tc_id: test.tc_id,
                        detail: format!(
                            "expected: {}\n  actual: {}",
                            exp_md.to_ascii_lowercase(),
                            actual_hex
                        ),
                    });
                }
            }
            Err(e) => {
                result_tests.push(ResultTest {
                    tc_id: test.tc_id,
                    md: None,
                    results_array: None,
                });
                summary.failures.push(TestFailure {
                    tg_id,
                    tc_id: test.tc_id,
                    detail: format!("error: {e}"),
                });
            }
        }
    }

    println!(
        "  AFT  [tgId={tg_id}]: {}/{} passed",
        group_pass,
        tests.len()
    );

    ResultGroup { tg_id, tests: result_tests }
}

fn run_mct(
    key: &str,
    tg_id: u64,
    tests: &[ShaPromptTest],
    expected: &HashMap<u64, &ShaExpectedTest>,
    summary: &mut TestSummary,
) -> ResultGroup {
    let mut group_pass = 0usize;
    let mut result_tests: Vec<ResultTest> = Vec::new();

    for test in tests {
        summary.total += 1;

        let result = (|| -> anyhow::Result<Vec<Vec<u8>>> {
            let seed_len_bits = test
                .len
                .ok_or_else(|| anyhow::anyhow!("MCT test missing len field"))? as usize;
            let seed = decode_msg(test.msg.as_deref(), test.len)?;
            let actual_results = if is_sha2(key) {
                mct_sha2(key, &seed, seed_len_bits)
            } else {
                mct_sha3(key, &seed)
            };
            Ok(actual_results)
        })();

        match result {
            Ok(actual_results) => {
                let entries: Vec<ResultMctEntry> = actual_results
                    .iter()
                    .map(|r| ResultMctEntry { md: hex::encode_upper(r) })
                    .collect();
                result_tests.push(ResultTest {
                    tc_id: test.tc_id,
                    md: None,
                    results_array: Some(entries),
                });

                let passed = expected
                    .get(&test.tc_id)
                    .and_then(|e| e.results_array.as_ref())
                    .map(|exp_arr| {
                        actual_results.len() == exp_arr.len()
                            && actual_results
                                .iter()
                                .zip(exp_arr.iter())
                                .all(|(a, e)| hex_eq(a, &e.md))
                    })
                    .unwrap_or(false);

                if passed {
                    summary.passed += 1;
                    group_pass += 1;
                } else {
                    summary.failures.push(TestFailure {
                        tg_id,
                        tc_id: test.tc_id,
                        detail: "MCT digest mismatch (see results_array)".into(),
                    });
                }
            }
            Err(e) => {
                result_tests.push(ResultTest {
                    tc_id: test.tc_id,
                    md: None,
                    results_array: None,
                });
                summary.failures.push(TestFailure {
                    tg_id,
                    tc_id: test.tc_id,
                    detail: format!("error: {e}"),
                });
            }
        }
    }

    println!(
        "  MCT  [tgId={tg_id}]: {}/{} passed",
        group_pass,
        tests.len()
    );

    ResultGroup { tg_id, tests: result_tests }
}

#[allow(dead_code)]
fn run_ldt(
    key: &str,
    tg_id: u64,
    tests: &[ShaPromptTest],
    expected: &HashMap<u64, &ShaExpectedTest>,
    summary: &mut TestSummary,
) {
    let mut group_pass = 0usize;

    for test in tests {
        summary.total += 1;

        let result = (|| -> anyhow::Result<bool> {
            let exp = expected
                .get(&test.tc_id)
                .ok_or_else(|| anyhow::anyhow!("missing expected for tcId={}", test.tc_id))?;
            let expected_md = exp
                .md
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("expected.md missing"))?;

            let lm = test
                .large_msg
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("largeMsg missing in LDT test"))?;

            let actual = hash_large_msg(key, lm)?;
            Ok(hex_eq(&actual, expected_md))
        })();

        match result {
            Ok(true) => {
                summary.passed += 1;
                group_pass += 1;
            }
            Ok(false) => {
                summary.failures.push(TestFailure {
                    tg_id,
                    tc_id: test.tc_id,
                    detail: "LDT digest mismatch".into(),
                });
            }
            Err(e) => {
                summary.failures.push(TestFailure {
                    tg_id,
                    tc_id: test.tc_id,
                    detail: format!("error: {e}"),
                });
            }
        }
    }

    println!(
        "  LDT  [tgId={tg_id}]: {}/{} passed",
        group_pass,
        tests.len()
    );
}

// ---------------------------------------------------------------------------
// MCT algorithms
// ---------------------------------------------------------------------------

/// SHA-1 / SHA-2 Monte Carlo Test (ACVP "Alternate MCT" variant).
///
/// The concatenated window message is normalized to `seed_len_bits` before
/// hashing: truncated if too long, zero-padded if too short.  This matches
/// ACVP test vectors where the initial seed is larger than 3 × DigestLen.
///
/// ```text
/// M[0] = M[1] = M[2] = seed  (seed_len_bits long)
/// for outer in 0..100:
///   for _ in 0..1000:
///     msg = M[0] || M[1] || M[2]
///     msg = truncate-or-zero-pad(msg, seed_len_bits)
///     new = Hash(msg)
///     M[0] = M[1]; M[1] = M[2]; M[2] = new
///   result[outer] = M[2]
///   M[0] = M[1] = M[2] = result[outer]
/// ```
fn mct_sha2(key: &str, seed: &[u8], seed_len_bits: usize) -> Vec<Vec<u8>> {
    // norm_len은 최소 3 × DigestLen 이어야 올바른 슬라이딩 윈도우 체인이 된다.
    // sha2-384처럼 seed가 DigestLen과 같을 때 이 조건이 중요하다.
    let digest_len = sha_hash(key, &[]).len();
    let norm_len = ((seed_len_bits + 7) / 8).max(3 * digest_len);
    let mut m0 = seed.to_vec();
    let mut m1 = seed.to_vec();
    let mut m2 = seed.to_vec();
    let mut results = Vec::with_capacity(100);

    for _ in 0..100 {
        for _ in 0..1000 {
            let msg_len = m0.len() + m1.len() + m2.len();
            let mut msg = Vec::with_capacity(msg_len.max(norm_len));
            msg.extend_from_slice(&m0);
            msg.extend_from_slice(&m1);
            msg.extend_from_slice(&m2);

            // Normalize to seed_len_bits
            if msg.len() >= norm_len {
                msg.truncate(norm_len);
            } else {
                msg.resize(norm_len, 0);
            }

            let digest = sha_hash(key, &msg);
            m0 = m1;
            m1 = m2;
            m2 = digest;
        }
        results.push(m2.clone());
        m0 = m2.clone();
        m1 = m2.clone();
        // m2 stays the same
    }

    results
}

/// SHA-3 Monte Carlo Test.
///
/// Algorithm:
/// ```text
/// current = seed
/// for outer in 0..100:
///   for _ in 0..1000:
///     current = Hash(current)
///   result[outer] = current
/// ```
fn mct_sha3(key: &str, seed: &[u8]) -> Vec<Vec<u8>> {
    let mut current = seed.to_vec();
    let mut results = Vec::with_capacity(100);

    for _ in 0..100 {
        for _ in 0..1000 {
            current = sha_hash(key, &current);
        }
        results.push(current.clone());
    }

    results
}

// ---------------------------------------------------------------------------
// LDT: Large Data Test (streamed to avoid OOM)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn hash_large_msg(key: &str, lm: &LargeMsg) -> anyhow::Result<Vec<u8>> {
    if lm.expansion_technique != "repeating" {
        anyhow::bail!(
            "unsupported LDT expansion technique: {}",
            lm.expansion_technique
        );
    }

    let raw = hex::decode(&lm.content)
        .map_err(|e| anyhow::anyhow!("LDT content hex decode: {e}"))?;
    let chunk_len = (lm.content_length as usize + 7) / 8;
    let chunk = &raw[..chunk_len.min(raw.len())];

    let total_bytes = lm.full_length as usize / 8;

    // Build a 1 MB buffer filled with repeating chunk to minimize update() calls.
    const BUF_SIZE: usize = 1024 * 1024;
    let mut buf = Vec::with_capacity(BUF_SIZE);
    while buf.len() < BUF_SIZE {
        let space = BUF_SIZE - buf.len();
        let take = chunk.len().min(space);
        buf.extend_from_slice(&chunk[..take]);
    }

    let mut hasher = StreamHasher::new(key);
    let mut written = 0usize;
    while written < total_bytes {
        let take = buf.len().min(total_bytes - written);
        hasher.update(&buf[..take]);
        written += take;
    }
    Ok(hasher.finalize())
}

/// Streaming hasher enum — avoids trait objects while supporting
/// all SHA variants in LDT.
#[allow(dead_code)]
enum StreamHasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha3_256(Sha3_256),
    Sha3_384(Sha3_384),
    Sha3_512(Sha3_512),
}

impl StreamHasher {
    fn new(key: &str) -> Self {
        match key {
            "sha2-256" => Self::Sha256(Sha256::new()),
            "sha2-384" => Self::Sha384(Sha384::new()),
            "sha2-512" => Self::Sha512(Sha512::new()),
            "sha3-256" => Self::Sha3_256(Sha3_256::new()),
            "sha3-384" => Self::Sha3_384(Sha3_384::new()),
            "sha3-512" => Self::Sha3_512(Sha3_512::new()),
            _ => unreachable!("unexpected sha key in StreamHasher: {}", key),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => Digest::update(h, data),
            Self::Sha384(h) => Digest::update(h, data),
            Self::Sha512(h) => Digest::update(h, data),
            Self::Sha3_256(h) => Digest::update(h, data),
            Self::Sha3_384(h) => Digest::update(h, data),
            Self::Sha3_512(h) => Digest::update(h, data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
            Self::Sha3_256(h) => h.finalize().to_vec(),
            Self::Sha3_384(h) => h.finalize().to_vec(),
            Self::Sha3_512(h) => h.finalize().to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Primitive helpers
// ---------------------------------------------------------------------------

/// One-shot hash for SHA-2 / SHA-3 (not SHAKE).
fn sha_hash(key: &str, msg: &[u8]) -> Vec<u8> {
    match key {
        "sha2-256" => Sha256::digest(msg).to_vec(),
        "sha2-384" => Sha384::digest(msg).to_vec(),
        "sha2-512" => Sha512::digest(msg).to_vec(),
        "sha3-256" => Sha3_256::digest(msg).to_vec(),
        "sha3-384" => Sha3_384::digest(msg).to_vec(),
        "sha3-512" => Sha3_512::digest(msg).to_vec(),
        _ => unreachable!("unexpected sha key: {}", key),
    }
}

/// XOF output for SHAKE-128 / SHAKE-256.
///
/// `out_bits` is the desired output length in **bits**.
/// If `out_bits` is not a multiple of 8, the unused low bits of the last
/// byte are zeroed (ACVP convention for partial-byte XOF output).
fn shake_xof(key: &str, msg: &[u8], out_bits: usize) -> Vec<u8> {
    let out_bytes = (out_bits + 7) / 8;
    let mut output = vec![0u8; out_bytes];
    match key {
        "shake-128" => {
            let mut h = Shake128::default();
            XofUpdate::update(&mut h, msg);
            h.finalize_xof().read(&mut output);
        }
        "shake-256" => {
            let mut h = Shake256::default();
            XofUpdate::update(&mut h, msg);
            h.finalize_xof().read(&mut output);
        }
        _ => unreachable!("unexpected shake key: {}", key),
    }

    // sha3 크레이트는 마지막 부분 바이트의 유효 r비트를 하위(LSB) 방향에 저장하지만
    // ACVP는 상위(MSB) 방향을 기대한다. 하위 r비트를 상위로 이동한다.
    let remainder = out_bits % 8;
    if remainder != 0 {
        if let Some(last) = output.last_mut() {
            *last <<= 8 - remainder;
        }
    }

    output
}

/// Decode the ACVP message hex string, trimmed to `len` bits.
/// A zero-length message is encoded as `msg="00", len=0` in ACVP.
fn decode_msg(msg_hex: Option<&str>, len_bits: Option<u64>) -> anyhow::Result<Vec<u8>> {
    let bits = len_bits.unwrap_or(0) as usize;
    if bits == 0 {
        return Ok(vec![]);
    }
    let hex = msg_hex.unwrap_or("00");
    let mut bytes =
        hex::decode(hex).map_err(|e| anyhow::anyhow!("msg hex decode failed: {e}"))?;
    let byte_len = (bits + 7) / 8;
    bytes.truncate(byte_len);
    Ok(bytes)
}

/// Case-insensitive hex comparison.
fn hex_eq(bytes: &[u8], expected_hex: &str) -> bool {
    hex::encode(bytes).eq_ignore_ascii_case(expected_hex)
}

fn is_shake(key: &str) -> bool {
    key.starts_with("shake-")
}

fn is_sha2(key: &str) -> bool {
    key.starts_with("sha2-")
}

fn is_sha3(key: &str) -> bool {
    key.starts_with("sha3-")
}

// ---------------------------------------------------------------------------
// SHA-2 비트 단위 해시 (FIPS 180-4)
// ---------------------------------------------------------------------------
//
// sha2 크레이트는 바이트 단위 API만 제공하므로 len % 8 != 0 인 경우
// SHA-384/512 압축 함수를 직접 구현한다.

// SHA-384 초기 해시값 (소수 9~16번째의 제곱근 소수 부분)
const SHA384_H0: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

// SHA-512 초기 해시값 (소수 1~8번째의 제곱근 소수 부분)
const SHA512_H0: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

// SHA-384/512 라운드 상수 K (소수 1~80번째의 세제곱근 소수 부분)
const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

// SHA-384/512 압축 함수 (1024-bit 블록, 64-bit 워드, 80라운드)
fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch)
            .wrapping_add(SHA512_K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g; g = f; f = e; e = d.wrapping_add(t1);
        d = c; c = b; b = a; a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a); state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c); state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e); state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g); state[7] = state[7].wrapping_add(h);
}

// SHA-384/512 비트 단위 해시 (FIPS 180-4)
// ACVP 마지막 바이트의 상위 r비트만 유효 (MSB-first 저장)
fn sha2_hash_bits(key: &str, data: &[u8], len_bits: usize) -> Vec<u8> {
    let r = len_bits % 8;
    let full_bytes = len_bits / 8;

    // FIPS 180-4 패딩: 유효 비트 다음에 '1' 비트 삽입
    let mut padded: Vec<u8> = data[..full_bytes].to_vec();
    if r == 0 {
        padded.push(0x80);
    } else {
        // 상위 r비트 보존 + 위치 r에 '1' 삽입
        let partial = data[full_bytes] & (0xFFu8 << (8 - r));
        padded.push(partial | (0x80 >> r));
    }

    // 길이 필드(16 bytes)를 위해 padded.len() % 128 == 112 가 될 때까지 0 패딩
    while padded.len() % 128 != 112 {
        padded.push(0);
    }
    // 128-bit big-endian 길이 (bits 단위, 상위 64비트 = 0)
    padded.extend_from_slice(&0u64.to_be_bytes());
    padded.extend_from_slice(&(len_bits as u64).to_be_bytes());

    let (mut state, out_words): ([u64; 8], usize) = match key {
        "sha2-384" => (SHA384_H0, 6),
        "sha2-512" => (SHA512_H0, 8),
        _ => unreachable!("sha2_hash_bits: unsupported key {}", key),
    };

    for block in padded.chunks(128) {
        sha512_compress(&mut state, block.try_into().unwrap());
    }

    let mut output = Vec::with_capacity(out_words * 8);
    for &word in &state[..out_words] {
        output.extend_from_slice(&word.to_be_bytes());
    }
    output
}

// ---------------------------------------------------------------------------
// SHA-3 비트 단위 해시 (FIPS 202)
// ---------------------------------------------------------------------------
//
// SHA-3는 임의 비트 길이의 입력을 받는 비트 지향 알고리즘이다.
// ACVP 테스트 벡터에서 비바이트 정렬 메시지(len % 8 != 0)는
// 마지막 바이트의 상위 r비트만 유효하다 (MSB-first 저장).
// FIPS 202 내부는 MSB-first와 동일하게 처리되므로
// 상위 r비트를 하위로 이동(>> (8-r))하여 도메인 비트를 이어붙인다.

fn sha3_hash_bits(key: &str, data: &[u8], len_bits: usize) -> Vec<u8> {
    // SHA-3 파라미터: (레이트 bytes, 출력 bytes)
    let (rate, out_len): (usize, usize) = match key {
        "sha3-256" => (136, 32),
        "sha3-384" => (104, 48),
        "sha3-512" => (72, 64),
        _ => unreachable!(),
    };

    let full_bytes = len_bits / 8;
    let r = len_bits % 8; // 마지막 바이트의 유효 비트 수

    // FIPS 202 패딩 구성
    let mut padded: Vec<u8> = data[..full_bytes].to_vec();

    if r == 0 {
        // 바이트 정렬: SHA-3 도메인(01) + 멀티레이트 패딩 시작(1) = 0x06
        padded.push(0x06);
    } else {
        // ACVP의 상위 r비트를 하위 r비트로 이동한 뒤
        // 도메인(01)과 패딩 시작(1) = 0x06을 이어붙임
        let partial = data[full_bytes] >> (8 - r);
        let combined = (partial as u16) | (0x06u16 << r);
        padded.push(combined as u8);
        if combined > 0xFF {
            // r >= 6이면 도메인/패딩 비트가 다음 바이트로 넘침
            padded.push((combined >> 8) as u8);
        }
    }

    // 멀티레이트 패딩(10*1): 레이트 경계까지 0으로 채우고 마지막 비트를 1로 설정.
    // 단, 패딩 시작 비트(bit7)가 이미 1인 채 블록 경계에 걸린 경우(r=5 edge case)
    // 같은 비트에 종료 비트를 덮어쓰면 안 되므로 새 블록을 추가한다.
    let current_len = padded.len();
    let next_block = if current_len % rate == 0 && padded[current_len - 1] & 0x80 != 0 {
        current_len + rate
    } else {
        ((current_len - 1) / rate + 1) * rate
    };
    padded.resize(next_block, 0);
    *padded.last_mut().unwrap() |= 0x80;

    // Keccak 스펀지 흡수
    let mut state = [0u64; 25];
    for block in padded.chunks(rate) {
        // 각 블록을 Little-Endian 64비트 레인으로 상태에 XOR
        for (i, lane_bytes) in block.chunks(8).enumerate() {
            let mut lane = 0u64;
            for (j, &b) in lane_bytes.iter().enumerate() {
                lane |= (b as u64) << (8 * j);
            }
            state[i] ^= lane;
        }
        keccak::f1600(&mut state);
    }

    // 상태에서 해시값 추출 (Little-Endian)
    let mut output = vec![0u8; out_len];
    for (i, chunk) in output.chunks_mut(8).enumerate() {
        let bytes = state[i].to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    output
}
