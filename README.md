# fips_tester

NIST ACVP 테스트 벡터(prompt.json + expectedResult.json)를 내려받아 각 알고리즘을 Rust로 재구현/검증하는 CLI 도구.

## 빌드 & 사용법

```bash
./build.sh                          # cargo build → ./fips_tester 에 복사
./fips_tester alglist               # 지원 알고리즘 목록
./fips_tester download <algo|all>   # 테스트 벡터 다운로드
./fips_tester test <algo|all>       # 테스트 실행
```

시스템 전제조건: `libssl-dev` (Ubuntu: `sudo apt install libssl-dev pkg-config`).

## 지원 알고리즘 (35종)

| 계열 | 알고리즘 keys |
|---|---|
| 해시 | `sha2-256/384/512`, `sha3-256/384/512`, `shake-128/256` |
| MAC | `hmac-sha2-256/384/512`, `hmac-sha3-256/384/512` |
| 대칭 | `aes-ecb`, `aes-cbc`, `aes-ctr`, `aes-gcm` |
| DRBG/KDF | `hmacdrbg`, `kdf` |
| ECDSA | `ecdsa-keygen`, `ecdsa-keyver`, `ecdsa-siggen`, `ecdsa-sigver` |
| EdDSA | `eddsa-keygen`, `eddsa-siggen`, `eddsa-sigver` |
| RSA | `rsa-keygen`, `rsa-siggen`, `rsa-sigver` |
| ML-KEM | `ml-kem-keygen`, `ml-kem-encapdecap` |
| ML-DSA | `ml-dsa-keygen`, `ml-dsa-siggen`, `ml-dsa-sigver` |

## 프로젝트 구조

```
src/
├── main.rs         CLI 진입점 ("alglist" / "download" / "test")
├── runner.rs       AlgoTester trait + TestSummary
├── testvec.rs      prompt.json / expectedResult.json 파서
└── algos/
    ├── mod.rs      make_tester(key) → 적절한 Tester 반환
    ├── sha.rs      SHA2/3, SHAKE
    ├── hmac.rs     HMAC-SHA2/3
    ├── aes.rs      AES ECB/CBC/CTR/GCM
    ├── hmac_drbg.rs
    ├── kdf.rs      SP 800-108 Counter/Feedback/DoublePipeline
    ├── ecdsa.rs    KeyGen/KeyVer/SigGen/SigVer
    ├── eddsa.rs    Ed25519/Ed448
    ├── rsa.rs      KeyGen/SigGen/SigVer (PKCS#1v1.5, PSS)
    ├── ml_kem.rs   ML-KEM-512/768/1024
    └── ml_dsa.rs   ML-DSA-44/65/87
```

### 공통 흐름

1. `main.rs`가 CLI 인자(`test <algo>` 또는 `all`)를 받음.
2. `algos::make_tester(key)`가 key에 맞는 `Box<dyn AlgoTester>`를 반환.
3. tester의 `.run(vec_dir)`가 실행됨.
4. 각 tester는 `testvec::load_prompt` / `load_expected`로 JSON을 로드 → 그룹/테스트 순회 → 검증 → `result.json`을 생성.
5. `TestSummary::print_result()`로 최종 결과 출력.

### 핵심 trait (`runner.rs`)

```rust
trait AlgoTester {
    fn run(&self, vec_dir: &Path) -> Result<TestSummary>;
}
struct TestSummary { algo, total, passed, failures }
```

## 알고리즘별 검증 함수

### SHA (sha.rs)
| 함수 | 역할 |
|---|---|
| `run_aft` | 단일 메시지 해시, `hex_eq`로 비교 |
| `run_mct` | 100 외부 × 1000 내부 반복 (SHA2/SHA3별로 다른 구성) |
| `sha_hash` | sha2/sha3 crate 디스패치 |
| `shake_xof` | XOF 출력 (비트 정렬 보정) |
| `sha2_hash_bits` / `sha3_hash_bits` | 비바이트 정렬 입력 수동 구현 (FIPS 180-4 / 202) |

### HMAC (hmac.rs)
| 함수 | 역할 |
|---|---|
| `run_aft` | 그룹 순회 |
| `hmac_mac` | `Hmac<D>` crate 디스패치 + `macLen/8` 바이트만 상위 truncate |

### AES (aes.rs)
| 함수 | 역할 |
|---|---|
| `run_aft_case` | 모드별 encrypt/decrypt 단일 블록 |
| `aes_ecb/cbc/ctr` | 블록체인 및 카운터 모드 (수동 구현, `aes` crate의 블록 cipher 위) |
| `aes_gcm_encrypt/decrypt` | IV=96bit는 `aes-gcm` crate, 그 외는 직접 GHASH |
| `ghash` / `gf128_mul` | GF(2^128) 곱셈, 임의 IV용 J0 유도 |
| `mct_ecb` | NIST CAVS ECB MCT (XOR 기반 키 업데이트) |
| `mct_cbc_encrypt/decrypt` | ACVP `MonteCarloAesCbc.cs`와 동일 (decrypt는 `CT[j+1] = PT[j-1]` lagged chain) |
| `mask_last_byte_bits` | CTR의 비바이트 정렬 길이 처리 |

### hmacDRBG (hmac_drbg.rs)
| 함수 | 역할 |
|---|---|
| `HmacDrbg::new` | SP 800-90A Instantiate (Key=0, V=1, update(seed_material)) |
| `update` | K=HMAC(K, V‖0x00‖data); V=HMAC(K, V); data 비어있지 않으면 0x01 변형 반복 |
| `reseed` | update(entropy‖addl_input) |
| `generate` | predResistance=true면 reseed 먼저, 그 후 V 반복 생성 |
| `hmac_with` | 11가지 해시 모드 디스패치 |

### KDF (kdf.rs)
| 함수 | 역할 |
|---|---|
| `derive_kdf` | kdf_mode 분기 (counter/feedback/double-pipeline) |
| `build_counter_message` | counter 위치별 메시지 조립 (`middle fixed data`는 `splice_bits`로 breakLocation에서 비트 삽입) |
| `build_feedback_message` | `before iterator` = `counter‖prev‖fixed`, `before fixed data` = `prev‖counter‖fixed` 등 |
| `mac_run` | 15가지 MAC (HMAC×11 + CMAC-AES×3 + CMAC-TDES) 디스패치 |
| `splice_bits` / `pack_bits_msb` | 비트 단위 ACVP BitString 조작 |

### ECDSA (ecdsa.rs)
| key | 검증 함수 |
|---|---|
| `ecdsa-keyver` | `key_valid` — `EcPoint::from_bytes` + `EcKey::from_public_key` (곡선 위에 있는지) |
| `ecdsa-sigver` | `verify_ecdsa` — `EcdsaSig::from_private_components` + `sig.verify(digest, key)` |
| `ecdsa-keygen` | `keygen_consistent` — 만들어진 `d·G == Q` 및 `EcKey::check_key()` |
| `ecdsa-siggen` | `verify_ecdsa`로 검증 (k가 랜덤이라 byte-match 불가). SP800-106 conformance는 `rs_in_range`로 r,s ∈ [1, n-1] 체크 |
| `hash_for_ecdsa` | SHA2/3/SHAKE 디스패치 (SHAKE는 128bit→32B, 256bit→64B) |
| `make_point` | (qx, qy) → SEC1 uncompressed → OpenSSL EcPoint |

### EdDSA (eddsa.rs)
| key | 검증 함수 |
|---|---|
| `eddsa-keygen` | `PKey::private_key_from_raw_bytes(d) → raw_public_key()` 바이트 비교 |
| `eddsa-siggen` | pure + context 없음 → openssl `Verifier::new_without_digest`. prehash/context는 구조 검증 (길이 일치) |
| `eddsa-sigver` | Ed25519는 `ed25519-dalek`의 `verify_strict` / `verify_prehashed`. Ed448 pure → openssl. Ed448 prehash → expected로 defer |

### RSA (rsa.rs)
| key | 검증 함수 |
|---|---|
| `rsa-keygen` | `rsa_keypair_consistent` — `n=p·q`, `gcd(e, p-1)=1`, `dmp1·e ≡ 1 mod p-1`, `dmq1·e ≡ 1 mod q-1`, `iqmp·q ≡ 1 mod p` (num-bigint) |
| `rsa-siggen` | `rsa_verify` (PKCS1v1.5 / PSS) — openssl `Verifier::set_rsa_padding` + `saltLen`. SHAKE / shake-mgf / SP800-106은 `sig_shape_matches` (길이만) |
| `rsa-sigver` | `rsa_verify` 후 `verified == expected_passed` 비교 |

### ML-KEM (ml_kem.rs) — `fips203` crate
| function | 검증 함수 |
|---|---|
| keygen | `KG::keygen_from_seed(d, z) → (ek, dk)` → 바이트 비교 |
| encapsulation | `EncapsKey::try_from_bytes → encaps_from_seed(m) → (ss, ct)` → 바이트 비교 |
| decapsulation | `DecapsKey::try_decaps(ct) → ss` → 바이트 비교 |
| encapsulationKeyCheck / decapsulationKeyCheck | `try_from_bytes` 성공 여부 = 유효 판정 |

### ML-DSA (ml_dsa.rs) — `fips204` crate
| key | 검증 함수 |
|---|---|
| `ml-dsa-keygen` | `KG::keygen_from_seed(&xi)` → (pk, sk) 바이트 비교 |
| `ml-dsa-siggen` | external/pure → `PrivateKey::get_public_key().verify(msg, sig, ctx)`. 그 외 (internal/prehash) → 서명 길이 확인 |
| `ml-dsa-sigver` | external/pure → `PublicKey::verify(msg, sig, ctx)` → expected와 비교. 그 외 → expected로 defer |

## 검증 방식 요약

1. **바이트 일치 (match)**: SHA, HMAC, AES, hmacDRBG, KDF, ML-KEM, ML-DSA KeyGen / deterministic SigGen
2. **공개키 검증 (verify)**: ECDSA/EdDSA/RSA SigGen, EdDSA/RSA/ML-DSA SigVer
3. **정합성 검증 (structural)**: ECDSA/RSA KeyGen, ECDSA SP800-106 SigGen
4. **구조 길이 확인 (shape)**: RSA SHAKE hash, ML-DSA prehash/internal 등 라이브러리 미지원 경로

각 tester는 모두 같은 `AlgoTester::run` 계약을 따르므로 `main.rs`의 디스패처는 알고리즘 수와 무관하게 동일하게 동작합니다.

## 제약사항

다음 경로는 라이브러리 한계로 완전한 암호학적 검증 대신 구조/길이 확인으로 통과 판정합니다:

- ECDSA SigGen SP800-106 conformance → r, s 범위만 검증
- RSA SHAKE-hash 또는 `maskFunction=shake-*` → 서명 길이 확인
- RSA SP800-106 conformance → 동일
- EdDSA Ed448 prehash / context → openssl crate의 context 파라미터 미지원으로 expected defer
- ML-DSA prehash 또는 `signatureInterface=internal` → fips204 외부 API 범위 밖

## 의존 crate

| 카테고리 | crate |
|---|---|
| 해시 | `sha1`, `sha2`, `sha3`, `keccak` |
| MAC | `hmac`, `cmac` |
| 대칭 암호 | `aes`, `aes-gcm`, `cipher`, `des` |
| ECDSA | `openssl` (모든 곡선 포함 B/K 이진 곡선) |
| EdDSA | `ed25519-dalek` (Ed25519), `openssl` (Ed448) |
| RSA | `openssl`, `num-bigint`, `num-integer`, `num-traits` |
| PQC | `fips203`, `fips204` (integritychain) |
| 기타 | `anyhow`, `serde`, `serde_json`, `hex`, `reqwest` |
