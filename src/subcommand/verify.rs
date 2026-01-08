use {super::*, std::collections::BTreeSet};

#[derive(Parser)]
pub(crate) struct Verify {
  #[arg(help = "Verify manifest fingerprint is <FINGERPRINT>", long)]
  fingerprint: Option<Hash>,
  #[arg(help = "Ignore missing files", long)]
  ignore_missing: bool,
  #[arg(help = "Verify that manifest has been signed by <KEY>", long)]
  key: Option<PublicKey>,
  #[arg(
    help = "Read manifest from <MANIFEST>, defaults to `<ROOT>/filepack.json`",
    long
  )]
  manifest: Option<Utf8PathBuf>,
  #[arg(help = "Print manifest if verification is successful", long)]
  print: bool,
  #[arg(help = "Verify files in <ROOT> directory against manifest, defaults to current directory")]
  root: Option<Utf8PathBuf>,
}

impl Verify {
  pub(crate) fn run(self, options: Options) -> Result {
    let current_dir = current_dir()?;

    let root = self.root.unwrap_or_else(|| current_dir.clone());

    let source = if let Some(ref manifest) = self.manifest {
      manifest.clone()
    } else {
      root.join(Manifest::FILENAME)
    };

    let json = filesystem::read_to_string_opt(&source)?.ok_or_else(|| {
      error::ManifestNotFound {
        path: self
          .manifest
          .as_deref()
          .unwrap_or(Utf8Path::new(Manifest::FILENAME)),
      }
      .build()
    })?;

    let manifest = serde_json::from_str::<Manifest>(&json).context(error::DeserializeManifest {
      path: Manifest::FILENAME,
    })?;

    let fingerprint = manifest.fingerprint();

    if let Some(expected) = self.fingerprint
      && fingerprint != expected
    {
      let style = Style::stderr();
      eprintln!(
        "\
fingerprint mismatch: `{source}`
            expected: {}
              actual: {}",
        expected.style(style.good()),
        fingerprint.style(style.bad()),
      );
      return Err(error::FingerprintMismatch.build());
    }

    let entries = manifest.files.entries();

    let total_size: u64 = entries
      .iter()
      .filter_map(|(_, entry)| match entry {
        Entry::File(file) => Some(file.size),
        Entry::Directory(_) => None,
      })
      .sum();

    let bar = progress_bar::new(&options, total_size);

    let mut mismatches = BTreeMap::new();

    let mut expected_paths = BTreeSet::new();

    for (path, entry) in &entries {
      expected_paths.insert(path.clone());

      match entry {
        Entry::Directory(_) => {
          let full_path = root.join(path);
          if !full_path.is_dir() {
            ensure! {
              self.ignore_missing,
              error::MissingDirectory { path },
            }
          }
        }
        Entry::File(expected) => {
          let actual = match options.hash_file(&root.join(path)) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
              ensure! {
                self.ignore_missing,
                error::MissingFile { path },
              }
              continue;
            }
            result => result.context(error::FilesystemIo { path })?,
          };

          if actual != *expected {
            mismatches.insert(path, (actual, expected));
          }

          bar.inc(expected.size);
        }
      }
    }

    if !mismatches.is_empty() {
      for (path, (actual, expected)) in &mismatches {
        let style = Style::stderr();

        let hash_style = if expected.hash == actual.hash {
          style.good()
        } else {
          style.bad()
        };

        let size_style = if expected.size == actual.size {
          style.good()
        } else {
          style.bad()
        };

        eprintln!(
          "\
mismatched file: `{path}`
       manifest: {} ({} bytes)
           file: {} ({} bytes)",
          expected.hash.style(style.good()),
          expected.size.style(style.good()),
          actual.hash.style(hash_style),
          actual.size.style(size_style),
        );
      }

      return Err(
        error::EntryMismatch {
          count: mismatches.len(),
        }
        .build(),
      );
    }

    for entry in WalkDir::new(&root) {
      let entry = entry?;

      let path = entry.path();

      let path = decode_path(path)?;

      if path == root {
        continue;
      }

      if current_dir.join(path) == current_dir.join(&source) {
        continue;
      }

      let path = path.strip_prefix(&root).unwrap();

      let path = RelativePath::try_from(path).context(error::Path { path })?;

      ensure! {
        expected_paths.contains(&path),
        error::ExtraneousFile { path },
      }
    }

    {
      let path = root.join(Metadata::FILENAME);

      if let Some(json) = filesystem::read_to_string_opt(&path)? {
        serde_json::from_str::<Metadata>(&json)
          .context(error::DeserializeMetadata { path: &path })?;
      }
    }

    for (public_key, signature) in &manifest.signatures {
      public_key.verify(fingerprint.as_bytes(), signature)?;
    }

    if let Some(key) = self.key {
      ensure! {
        manifest.signatures.contains_key(&key),
        error::SignatureMissing { key },
      }
    }

    if self.print {
      print!("{json}");
    }

    Ok(())
  }
}
