use super::*;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Manifest {
  #[serde(default, skip_serializing_if = "Directory::is_empty")]
  pub files: Directory,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub signatures: BTreeMap<PublicKey, Signature>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", untagged)]
pub enum Entry {
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
pub struct File {
  pub hash: Hash,
  pub size: u64,
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
pub struct Directory {
  entries: BTreeMap<Component, Entry>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", transparent)]
struct Component(String);

impl Component {
  fn as_bytes(&self) -> &[u8] {
    self.0.as_bytes()
  }

  fn as_str(&self) -> &str {
    &self.0
  }

  fn len(&self) -> u64 {
    self.0.len().into_u64()
  }
}

impl Directory {
  pub fn insert_directory(&mut self, path: &RelativePath) {
    self.insert_entry(path, Entry::Directory(Directory::default()));
  }

  pub fn insert_file(&mut self, path: &RelativePath, file: File) {
    self.insert_entry(path, Entry::File(file));
  }

  pub fn entries(&self) -> Vec<(RelativePath, Entry)> {
    let mut entries = Vec::new();
    self.collect_entries(None, &mut entries);
    entries
  }

  fn collect_entries(&self, prefix: Option<&str>, entries: &mut Vec<(RelativePath, Entry)>) {
    for (component, entry) in &self.entries {
      let path = match prefix {
        Some(prefix) => format!("{prefix}/{}", component.as_str()),
        None => component.as_str().to_string(),
      };

      let relative = path.parse::<RelativePath>().unwrap();

      entries.push((relative.clone(), entry.clone()));

      if let Entry::Directory(directory) = entry {
        directory.collect_entries(Some(&path), entries);
      }
    }
  }

  fn insert_entry(&mut self, path: &RelativePath, entry: Entry) {
    let components: Vec<Component> = path
      .str()
      .split('/')
      .map(|component| Component(component.to_owned()))
      .collect();

    self.insert_components(&components, entry);
  }

  fn insert_components(&mut self, components: &[Component], entry: Entry) {
    let Some((first, rest)) = components.split_first() else {
      return;
    };

    if rest.is_empty() {
      match self.entries.entry(first.clone()) {
        std::collections::btree_map::Entry::Vacant(vacant) => {
          vacant.insert(entry);
        }
        std::collections::btree_map::Entry::Occupied(mut occupied) => {
          if matches!(occupied.get(), Entry::Directory(_)) && matches!(entry, Entry::Directory(_)) {
            return;
          }

          occupied.insert(entry);
        }
      }

      return;
    }

    let child = self
      .entries
      .entry(first.clone())
      .or_insert_with(|| Entry::Directory(Directory::default()));

    if let Entry::Directory(directory) = child {
      directory.insert_components(rest, entry);
    }
  }

  fn fingerprint(&self) -> Hash {
    let mut hasher = FieldHasher::new(DIRECTORY_CONTEXT);

    hasher.update(0, &self.entries.len().into_u64().to_le_bytes());

    for (component, entry) in &self.entries {
      hasher.update(1, component.as_bytes());
      hasher.update(2, entry.fingerprint().as_bytes());
    }

    hasher.finalize()
  }

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

impl Manifest {
  pub(crate) const FILENAME: &'static str = "filepack.json";

  pub(crate) fn fingerprint(&self) -> Hash {
    self.files.fingerprint()
  }

  pub fn load(path: Option<&Utf8Path>) -> Result<(Utf8PathBuf, Self)> {
    let path = if let Some(path) = path {
      if filesystem::metadata(path)?.is_dir() {
        path.join(Manifest::FILENAME)
      } else {
        path.into()
      }
    } else {
      current_dir()?.join(Manifest::FILENAME)
    };

    let json = filesystem::read_to_string_opt(&path)?
      .ok_or_else(|| error::ManifestNotFound { path: &path }.build())?;

    let manifest =
      serde_json::from_str(&json).context(error::DeserializeManifest { path: &path })?;

    Ok((path, manifest))
  }

  pub fn save(&self, path: &Utf8Path) -> Result<()> {
    filesystem::write(path, format!("{}\n", serde_json::to_string(self).unwrap()))
  }
}

#[cfg(test)]
mod tests {
  use {super::*, regex::Regex};

  #[test]
  fn contexts_are_unique() {
    const ARRAY: [&str; 2] = [FILE_CONTEXT, DIRECTORY_CONTEXT];

    let map = BTreeSet::from(ARRAY);

    assert_eq!(map.len(), ARRAY.len());
  }

  #[test]
  fn manifests_in_readme_are_valid() {
    let readme = filesystem::read_to_string("README.md").unwrap();

    let re = Regex::new(r"(?s)```json(.*?)```").unwrap();

    for capture in re.captures_iter(&readme) {
      serde_json::from_str::<Manifest>(&capture[1]).unwrap();
    }
  }

  #[test]
  fn empty_manifest_serialization() {
    let manifest = Manifest {
      files: Directory::default(),
      signatures: BTreeMap::new(),
    };
    let json = serde_json::to_string(&manifest).unwrap();
    assert_eq!(json, "{}");
    assert_eq!(serde_json::from_str::<Manifest>(&json).unwrap(), manifest);
  }
}
