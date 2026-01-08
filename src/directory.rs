use super::*;

const DIRECTORY_CONTEXT: &str = "directory";

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", transparent)]
pub struct Directory {
  pub(crate) entries: BTreeMap<Component, Entry>,
}

impl Directory {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  pub(crate) fn fingerprint(&self) -> Hash {
    let mut hasher = FieldHasher::new(DIRECTORY_CONTEXT);

    hasher.update(0, &self.entries.len().into_u64().to_le_bytes());

    for (component, entry) in &self.entries {
      hasher.update(1, component.as_bytes());
      hasher.update(2, entry.fingerprint().as_bytes());
    }

    hasher.finalize()
  }

  pub(crate) fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }

  pub(crate) fn insert(&mut self, component: Component, entry: Entry) {
    self.entries.insert(component, entry);
  }
}
