use super::*;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Manifest {
  #[serde(default, skip_serializing_if = "Directory::is_empty")]
  files: Directory,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  signatures: BTreeMap<PublicKey, Signature>,
}

#[repr(u8)]
enum Tag {
  Directory = 0,
  File = 1,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", untagged)]
enum Entry {
  Directory(Directory),
  File(File),
}

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
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[Tag::File as u8]);
    hasher.update(&self.size.to_le_bytes());
    hasher.update(self.hash.as_bytes());
    hasher.finalize().into()
  }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", transparent)]
struct Directory {
  entries: BTreeMap<RelativePath, Entry>,
}

impl Directory {
  fn fingerprint(&self) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[Tag::Directory as u8]);

    for (path, entry) in &self.entries {
      hasher.update(&path.str().len().to_le_bytes());
      hasher.update(&path.str().as_bytes());
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
