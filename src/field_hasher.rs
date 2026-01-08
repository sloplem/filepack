use super::*;

pub(crate) struct FieldHasher(Hasher);

impl FieldHasher {
  pub(crate) fn new(context: &str) -> Self {
    Self(Hasher::new_derive_key(&format!("filepack:0:{context}")))
  }

  pub(crate) fn update(&mut self, tag: u8, contents: &[u8]) {
    self.0.update(&[tag]);
    self.0.update(&contents.len().into_u64().to_le_bytes());
    self.0.update(contents);
  }

  pub(crate) fn finalize(self) -> Hash {
    self.0.finalize().into()
  }
}
