use {
  assert_cmd::Command,
  assert_fs::{
    TempDir,
    assert::PathAssert,
    fixture::{ChildPath, FileTouch, FileWriteBin, FileWriteStr, PathChild, PathCreateDir},
  },
  camino::Utf8Path,
  filepack::{Directory, File, Hash, Manifest, PublicKey, Signature},
  predicates::str::RegexPredicate,
  std::{collections::BTreeMap, fs, path::Path, str},
};

trait ChildPathExt {
  fn utf8_path(&self) -> &Utf8Path;
}

impl ChildPathExt for ChildPath {
  fn utf8_path(&self) -> &Utf8Path {
    self.path().try_into().unwrap()
  }
}

fn path(message: &str) -> String {
  message.replace('/', std::path::MAIN_SEPARATOR_STR)
}

fn is_match<S>(pattern: S) -> RegexPredicate
where
  S: AsRef<str>,
{
  predicates::prelude::predicate::str::is_match(format!("^(?s){}$", pattern.as_ref())).unwrap()
}

fn load_key(path: &Path) -> String {
  fs::read_to_string(path).unwrap().trim().into()
}

fn file_entry(contents: &[u8]) -> File {
  File {
    hash: Hash::from(blake3::hash(contents)),
    size: contents.len() as u64,
  }
}

fn manifest_json<F>(builder: F) -> String
where
  F: FnOnce(&mut Directory),
{
  let mut files = Directory::default();
  builder(&mut files);
  format!(
    "{}\n",
    serde_json::to_string(&Manifest {
      files,
      signatures: BTreeMap::new(),
    })
    .unwrap()
  )
}

mod create;
mod fingerprint;
mod hash;
mod key;
mod keygen;
mod man;
mod misc;
mod sign;
mod verify;
