use super::*;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Manifest {
  #[serde(default, skip_serializing_if = "Directory::is_empty")]
  files: Directory,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  signatures: BTreeMap<PublicKey, Signature>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", untagged)]
enum Entry {
  Directory(Directory),
  File(File),
}

const FILE_CONTEXT: &str = "file";
const DIRECTORY_CONTEXT: &str = "directory";

impl Entry {
  fn fingerprint(&self) -> Hash {
    match self {
      Self::Directory(directory) => directory.fingerprint(),
      Self::File(file) => file.fingerprint(),
    }
  }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct File {
  hash: Hash,
  size: u64,
}

impl File {
  fn fingerprint(&self) -> Hash {
    let mut hasher = FieldHasher::new(FILE_CONTEXT);
    hasher.update(0, &self.size.to_le_bytes());
    hasher.update(1, self.hash.as_bytes());
    hasher.finalize()
  }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", transparent)]
struct Directory {
  entries: BTreeMap<Component, Entry>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", transparent)]
struct Component(String);

impl Component {
  fn as_bytes(&self) -> &[u8] {
    self.0.as_bytes()
  }

  fn len(&self) -> u64 {
    self.0.len().into_u64()
  }
}

impl Directory {
  fn fingerprint(&self) -> Hash {
    let mut hasher = FieldHasher::new(DIRECTORY_CONTEXT);

    hasher.update(0, &self.entries.len().into_u64().to_le_bytes());

    for (component, entry) in &self.entries {
      hasher.update(1, component.as_bytes());
      hasher.update(2, entry.fingerprint().as_bytes());
    }

    hasher.finalize()
  }
}

impl Directory {
  fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }
}

struct FieldHasher(Hasher);

impl FieldHasher {
  fn new(context: &str) -> Self {
    Self(Hasher::new_derive_key(&format!("filepack:0:{context}")))
  }

  fn update(&mut self, tag: u8, contents: &[u8]) {
    self.0.update(&[tag]);
    self.0.update(&contents.len().into_u64().to_le_bytes());
    self.0.update(contents);
  }

  fn finalize(self) -> Hash {
    self.0.finalize().into()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn contexts_are_unique() {
    const ARRAY: [&str; 2] = [FILE_CONTEXT, DIRECTORY_CONTEXT];

    let map = BTreeSet::from(ARRAY);

    assert_eq!(map.len(), ARRAY.len());
  }
}
