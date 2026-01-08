use super::*;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", untagged)]
pub enum Entry {
  Directory(Directory),
  File(File),
}

impl Entry {
  pub(crate) fn fingerprint(&self) -> Hash {
    match self {
      Self::Directory(directory) => directory.fingerprint(),
      Self::File(file) => file.fingerprint(),
    }
  }
}
