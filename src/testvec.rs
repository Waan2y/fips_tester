use serde::Deserialize;
use std::path::Path;

/// All algorithms share this outer envelope for prompt.json.
/// Inner test group contents are kept as raw JSON values because
/// each algorithm family defines its own group/test fields.
#[derive(Deserialize)]
pub struct PromptFile {
    #[allow(dead_code)]
    pub algorithm: String,
    #[allow(dead_code)]
    pub revision: String,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<serde_json::Value>,
}

/// All algorithms share this outer envelope for expectedResult.json.
#[derive(Deserialize)]
pub struct ExpectedFile {
    #[serde(rename = "vsId")]
    pub vs_id: u64,
    pub algorithm: String,
    pub revision: String,
    #[serde(rename = "isSample")]
    pub is_sample: bool,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<serde_json::Value>,
}

pub fn load_prompt(vec_dir: &Path) -> anyhow::Result<PromptFile> {
    let path = vec_dir.join("prompt.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {}", path.display(), e))?;
    serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("cannot parse {}: {}", path.display(), e))
}

pub fn load_expected(vec_dir: &Path) -> anyhow::Result<ExpectedFile> {
    let path = vec_dir.join("expectedResult.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {}", path.display(), e))?;
    serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("cannot parse {}: {}", path.display(), e))
}
