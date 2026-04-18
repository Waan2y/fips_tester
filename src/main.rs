mod algos;
mod runner;
mod testvec;

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const RAW_BASE_URL: &str =
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files";

// ACVP-Server commonly uses "expectedResults.json" (plural), but the requested
// local filename is "expectedResult.json" (singular). We'll store it locally as
// "expectedResult.json" while accepting either remote name.
const PROMPT_REMOTE: &str = "prompt.json";
const EXPECTED_LOCAL: &str = "expectedResult.json";
const EXPECTED_REMOTE_CANDIDATES: [&str; 2] = ["expectedResult.json", "expectedResults.json"];

struct Algo {
    key: &'static str,
    folder: &'static str,
}

// CLI algorithm key -> ACVP-Server folder mapping.
static ALGOS: &[Algo] = &[
    Algo {
        key: "aes-ecb",
        folder: "ACVP-AES-ECB-1.0",
    },
    Algo {
        key: "aes-ctr",
        folder: "ACVP-AES-CTR-1.0",
    },
    Algo {
        key: "aes-cbc",
        folder: "ACVP-AES-CBC-1.0",
    },
    Algo {
        key: "aes-gcm",
        folder: "ACVP-AES-GCM-1.0",
    },
    Algo {
        key: "ecdsa-keygen",
        folder: "ECDSA-KeyGen-FIPS186-5",
    },
    Algo {
        key: "ecdsa-keyver",
        folder: "ECDSA-KeyVer-FIPS186-5",
    },
    Algo {
        key: "ecdsa-siggen",
        folder: "ECDSA-SigGen-FIPS186-5",
    },
    Algo {
        key: "ecdsa-sigver",
        folder: "ECDSA-SigVer-FIPS186-5",
    },
    Algo {
        key: "eddsa-keygen",
        folder: "EDDSA-KeyGen-1.0",
    },
    Algo {
        key: "eddsa-siggen",
        folder: "EDDSA-SigGen-1.0",
    },
    Algo {
        key: "eddsa-sigver",
        folder: "EDDSA-SigVer-1.0",
    },
    Algo {
        key: "hmac-sha2-256",
        folder: "HMAC-SHA2-256-2.0",
    },
    Algo {
        key: "hmac-sha2-384",
        folder: "HMAC-SHA2-384-2.0",
    },
    Algo {
        key: "hmac-sha2-512",
        folder: "HMAC-SHA2-512-2.0",
    },
    Algo {
        key: "hmac-sha3-256",
        folder: "HMAC-SHA3-256-2.0",
    },
    Algo {
        key: "hmac-sha3-384",
        folder: "HMAC-SHA3-384-2.0",
    },
    Algo {
        key: "hmac-sha3-512",
        folder: "HMAC-SHA3-512-2.0",
    },
    Algo {
        key: "ml-dsa-keygen",
        folder: "ML-DSA-keyGen-FIPS204",
    },
    Algo {
        key: "ml-dsa-siggen",
        folder: "ML-DSA-sigGen-FIPS204",
    },
    Algo {
        key: "ml-dsa-sigver",
        folder: "ML-DSA-sigVer-FIPS204",
    },
    Algo {
        key: "ml-kem-keygen",
        folder: "ML-KEM-keyGen-FIPS203",
    },
    Algo {
        key: "ml-kem-encapdecap",
        folder: "ML-KEM-encapDecap-FIPS203",
    },
    Algo {
        key: "rsa-keygen",
        folder: "RSA-KeyGen-FIPS186-5",
    },
    Algo {
        key: "rsa-siggen",
        folder: "RSA-SigGen-FIPS186-5",
    },
    Algo {
        key: "rsa-sigver",
        folder: "RSA-SigVer-FIPS186-5",
    },
    Algo {
        key: "sha2-256",
        folder: "SHA2-256-1.0",
    },
    Algo {
        key: "sha2-384",
        folder: "SHA2-384-1.0",
    },
    Algo {
        key: "sha2-512",
        folder: "SHA2-512-1.0",
    },
    Algo {
        key: "sha3-256",
        folder: "SHA3-256-2.0",
    },
    Algo {
        key: "sha3-384",
        folder: "SHA3-384-2.0",
    },
    Algo {
        key: "sha3-512",
        folder: "SHA3-512-2.0",
    },
    Algo {
        key: "shake-128",
        folder: "SHAKE-128-FIPS202",
    },
    Algo {
        key: "shake-256",
        folder: "SHAKE-256-FIPS202",
    },
    Algo {
        key: "hmacdrbg",
        folder: "hmacDRBG-1.0",
    },
    Algo {
        key: "kdf",
        folder: "KDF-1.0",
    },
];

fn print_usage() {
    println!("Usage:");
    println!("  ./fips_tester alglist");
    println!("  ./fips_tester download <algorithm|all>");
    println!("  ./fips_tester test <algorithm|all>");
}

fn print_list() {
    println!("Available algorithms:");
    for a in ALGOS {
        println!("  {}", a.key);
    }
    println!();
    print_usage();
}

fn eprintln_x_red(msg: &str) {
    // Red "X ..." to match the requested error format.
    eprintln!("\x1b[31mX {}\x1b[0m", msg);
}

fn find_algo(key: &str) -> Option<&'static Algo> {
    ALGOS.iter().find(|a| a.key == key)
}

fn download_file(
    client: &reqwest::blocking::Client,
    url: &str,
    out_path: &Path,
) -> anyhow::Result<()> {
    let resp = client.get(url).send()?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!("404 Not Found");
    }
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let bytes = resp.bytes()?;
    let mut f = fs::File::create(out_path)?;
    f.write_all(&bytes)?;
    Ok(())
}

fn download_algo(
    client: &reqwest::blocking::Client,
    algo: &Algo,
    out_root: &Path,
) -> anyhow::Result<usize> {
    println!("Downloading {}...", algo.key);
    let mut downloaded = 0usize;

    // prompt.json
    {
        let url = format!("{}/{}/{}", RAW_BASE_URL, algo.folder, PROMPT_REMOTE);
        let out_path: PathBuf = out_root.join(algo.folder).join(PROMPT_REMOTE);
        print!("  - {} ... ", PROMPT_REMOTE);
        std::io::stdout().flush().ok();

        match download_file(client, &url, &out_path) {
            Ok(()) => {
                println!("OK");
                downloaded += 1;
            }
            Err(e) => {
                println!("FAIL");
                anyhow::bail!("{}: {}", PROMPT_REMOTE, e);
            }
        }
    }

    // expectedResult.json (download from either remote name)
    {
        let out_path: PathBuf = out_root.join(algo.folder).join(EXPECTED_LOCAL);
        print!("  - {} ... ", EXPECTED_LOCAL);
        std::io::stdout().flush().ok();

        let mut last_err: Option<anyhow::Error> = None;
        let mut ok = false;
        for remote in EXPECTED_REMOTE_CANDIDATES {
            let url = format!("{}/{}/{}", RAW_BASE_URL, algo.folder, remote);
            match download_file(client, &url, &out_path) {
                Ok(()) => {
                    ok = true;
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }

        if ok {
            println!("OK");
            downloaded += 1;
        } else {
            println!("FAIL");
            anyhow::bail!(
                "{}: {}",
                EXPECTED_LOCAL,
                last_err.unwrap_or_else(|| anyhow::anyhow!("unknown error"))
            );
        }
    }

    println!(
        "Done! {} files saved to {}/{}",
        downloaded,
        out_root.display(),
        algo.folder
    );
    Ok(downloaded)
}

fn main() {
    // Keep dependencies simple: blocking HTTP + filesystem writes.
    // We use a dedicated user-agent since GitHub rejects requests without one.
    let client = match reqwest::blocking::Client::builder()
        .user_agent("fips_tester/0.1")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln_x_red(&format!("Error: failed to build HTTP client: {}", e));
            std::process::exit(1);
        }
    };

    let args: Vec<String> = env::args().collect();
    let out_root = Path::new("testvectors");

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "alglist" => {
            print_list();
        }
        "download" => {
            if args.len() < 3 {
                print_usage();
                return;
            }
            let target = args[2].trim().to_ascii_lowercase();

            if target == "all" {
                let mut total = 0usize;
                for algo in ALGOS {
                    match download_algo(&client, algo, out_root) {
                        Ok(n) => total += n,
                        Err(e) => {
                            eprintln_x_red(&format!(
                                "Error: failed downloading '{}': {}",
                                algo.key, e
                            ));
                            std::process::exit(1);
                        }
                    }
                }
                println!("Total: {} files downloaded", total);
                return;
            }

            let Some(algo) = find_algo(&target) else {
                eprintln_x_red(&format!("Error: Unknown algorithm '{}'", target));
                eprintln_x_red("Use './fips_tester alglist' to see available algorithms");
                std::process::exit(2);
            };

            if let Err(e) = download_algo(&client, algo, out_root) {
                eprintln_x_red(&format!("Error: failed downloading '{}': {}", algo.key, e));
                std::process::exit(1);
            }
        }
        "test" => {
            if args.len() < 3 {
                print_usage();
                return;
            }
            let target = args[2].trim().to_ascii_lowercase();

            let out_root = Path::new("testvectors");

            if target == "all" {
                let mut any_failed = false;
                for algo in ALGOS {
                    let Some(tester) = algos::make_tester(algo.key) else {
                        continue; // not yet implemented
                    };
                    let vec_dir = out_root.join(algo.folder);
                    match tester.run(&vec_dir) {
                        Ok(summary) => {
                            if !summary.all_passed() {
                                any_failed = true;
                            }
                            summary.print_result();
                        }
                        Err(e) => {
                            eprintln_x_red(&format!(
                                "Error running '{}': {}",
                                algo.key, e
                            ));
                            any_failed = true;
                        }
                    }
                }
                if any_failed {
                    std::process::exit(1);
                }
            } else {
                let Some(algo) = find_algo(&target) else {
                    eprintln_x_red(&format!("Error: Unknown algorithm '{}'", target));
                    eprintln_x_red("Use './fips_tester alglist' to see available algorithms");
                    std::process::exit(2);
                };

                let Some(tester) = algos::make_tester(algo.key) else {
                    eprintln_x_red(&format!(
                        "Error: no tester implemented yet for '{}'",
                        algo.key
                    ));
                    std::process::exit(1);
                };

                let vec_dir = out_root.join(algo.folder);
                match tester.run(&vec_dir) {
                    Ok(summary) => {
                        summary.print_result();
                        if !summary.all_passed() {
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln_x_red(&format!("Error: {}", e));
                        std::process::exit(1);
                    }
                }
            }
        }
        other => {
            eprintln_x_red(&format!("Error: Unknown command '{}'", other));
            eprintln_x_red("Use './fips_tester alglist' to see available algorithms");
            std::process::exit(2);
        }
    }
}
