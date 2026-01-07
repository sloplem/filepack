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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct File {
  hash: Hash,
  size: u64,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", transparent)]
struct Directory {
  entries: BTreeMap<RelativePath, Entry>,
}

impl Directory {
  fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }
}
