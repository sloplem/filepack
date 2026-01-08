use super::*;

const FILE_CONTEXT: &str = "file";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct File {
  pub hash: Hash,
  pub size: u64,
}

impl File {
  pub(crate) fn new(hash: Hash, size: u64) -> Self {
    Self { hash, size }
  }

  pub(crate) fn fingerprint(&self) -> Hash {
    let mut hasher = FieldHasher::new(FILE_CONTEXT);
    hasher.update(0, &self.size.to_le_bytes());
    hasher.update(1, self.hash.as_bytes());
    hasher.finalize()
  }
}
