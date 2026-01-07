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

const FILE_CONTEXT: &str = "com.filepack:0:file";
const DIRECTORY_CONTEXT: &str = "com.filepack:0:directory";

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
    let mut hasher = Hasher::new_derive_key(FILE_CONTEXT);
    hasher.update(&self.size.to_le_bytes());
    hasher.update(self.hash.as_bytes());
    hasher.finalize().into()
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
    let mut hasher = Hasher::new_derive_key(DIRECTORY_CONTEXT);

    for (component, entry) in &self.entries {
      hasher.update(&component.len().to_le_bytes());
      hasher.update(&component.as_bytes());
      hasher.update(entry.fingerprint().as_bytes());
    }

    hasher.finalize().into()
  }
}

impl Directory {
  fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn contexts_are_unique() {
    const ARRAY: [&str; 2] = [FILE_CONTEXT, DIRECTORY_CONTEXT];

    let map = ARRAY.into::<BTreeMap>();

    assert_eq!(map.len(), ARRAY.len());

    for context in ARRAY {
      assert!(context.starts_with("filepack:0:"));
    }
  }
}
