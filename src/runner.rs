use std::path::Path;

/// Implemented by each algorithm family (sha, hmac, aes, …).
/// A single tester handles all variants within its family
/// (e.g., ShaTester handles sha2-256/sha3-512/shake-128/…).
pub trait AlgoTester: Send + Sync {
    /// Run all test cases found in `vec_dir` (which contains prompt.json +
    /// expectedResult.json) and return a summary.
    ///
    /// Implementations should print per-group progress to stdout as they run.
    fn run(&self, vec_dir: &Path) -> anyhow::Result<TestSummary>;
}

pub struct TestSummary {
    pub algo: String,
    pub total: usize,
    pub passed: usize,
    pub failures: Vec<TestFailure>,
}

pub struct TestFailure {
    pub tg_id: u64,
    pub tc_id: u64,
    #[allow(dead_code)]
    pub detail: String,
}

impl TestSummary {
    pub fn all_passed(&self) -> bool {
        self.failures.is_empty()
    }

    pub fn print_result(&self) {
        if self.all_passed() {
            println!(
                "\x1b[32m✓ {}: ALL PASSED ({} tests)\x1b[0m",
                self.algo, self.total
            );
        } else {
            println!(
                "\x1b[31mX {}: {} FAILED / {} total\x1b[0m",
                self.algo,
                self.failures.len(),
                self.total
            );
            for f in &self.failures {
                println!("    tgId={} tcId={} \x1b[31mFAIL\x1b[0m", f.tg_id, f.tc_id);
            }
        }
    }
}
