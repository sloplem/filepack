use super::*;

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

    let total_size = Self::calculate_total_size(&manifest.files);
    let bar = progress_bar::new(&options, total_size);

    let mut mismatches = BTreeMap::new();

    Self::verify_directory(
      &options,
      &root,
      &Utf8PathBuf::new(),
      &manifest.files,
      &mut mismatches,
      &bar,
      self.ignore_missing,
    )?;

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

    Self::check_extraneous_entries(&root, &current_dir, &source, &manifest.files)?;

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

    Self::verify_empty_directories(&root, &Utf8PathBuf::new(), &manifest.files)?;

    if self.print {
      print!("{json}");
    }

    Ok(())
  }

  fn calculate_total_size(directory: &Directory) -> u64 {
    let mut total = 0;
    for entry in directory.entries.values() {
      match entry {
        Entry::File(file) => total += file.size,
        Entry::Directory(dir) => total += Self::calculate_total_size(dir),
      }
    }
    total
  }

  fn verify_directory(
    options: &Options,
    root: &Utf8Path,
    current_path: &Utf8Path,
    directory: &Directory,
    mismatches: &mut BTreeMap<Utf8PathBuf, (File, File)>,
    bar: &ProgressBar,
    ignore_missing: bool,
  ) -> Result {
    for (component, entry) in &directory.entries {
      let entry_path = current_path.join(component.as_str());

      match entry {
        Entry::File(expected) => {
          let full_path = root.join(&entry_path);
          let actual = match options.hash_file(&full_path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
              let relative_path =
                RelativePath::try_from(entry_path.as_path()).context(error::Path { path: &entry_path })?;
              ensure! {
                ignore_missing,
                error::MissingFile {
                  path: relative_path,
                },
              }
              continue;
            }
            result => result.context(error::FilesystemIo { path: &entry_path })?,
          };

          if &actual != expected {
            mismatches.insert(entry_path, (actual.clone(), expected.clone()));
          }

          bar.inc(expected.size);
        }
        Entry::Directory(subdir) => {
          Self::verify_directory(
            options,
            root,
            &entry_path,
            subdir,
            mismatches,
            bar,
            ignore_missing,
          )?;
        }
      }
    }
    Ok(())
  }

  fn check_extraneous_entries(
    root: &Utf8Path,
    current_dir: &Utf8Path,
    source: &Utf8Path,
    directory: &Directory,
  ) -> Result {
    for entry in WalkDir::new(root) {
      let entry = entry?;

      let path = entry.path();
      let path = decode_path(path)?;

      if entry.file_type().is_dir() {
        if path == root {
          continue;
        }

        let relative = path.strip_prefix(root).unwrap();
        let relative_path = RelativePath::try_from(relative).context(error::Path { path: relative })?;

        if !Self::directory_contains_path(directory, &relative_path) {
          return Err(error::ExtraneousFile { path: &relative_path }.build());
        }

        continue;
      }

      if current_dir.join(path) == current_dir.join(source) {
        continue;
      }

      let relative = path.strip_prefix(root).unwrap();
      let relative_path = RelativePath::try_from(relative).context(error::Path { path: relative })?;

      if !Self::directory_contains_path(directory, &relative_path) {
        return Err(error::ExtraneousFile { path: &relative_path }.build());
      }
    }

    Ok(())
  }

  fn directory_contains_path(directory: &Directory, path: &RelativePath) -> bool {
    let components: Vec<&str> = path.str().split('/').collect();
    Self::directory_contains_components(directory, &components)
  }

  fn directory_contains_components(directory: &Directory, components: &[&str]) -> bool {
    if components.is_empty() {
      return true;
    }

    let component = Component::from(components[0]);

    if let Some(entry) = directory.entries.get(&component) {
      if components.len() == 1 {
        true
      } else {
        match entry {
          Entry::Directory(subdir) => Self::directory_contains_components(subdir, &components[1..]),
          Entry::File(_) => false,
        }
      }
    } else {
      false
    }
  }

  fn verify_empty_directories(
    root: &Utf8Path,
    current_path: &Utf8Path,
    directory: &Directory,
  ) -> Result {
    for (component, entry) in &directory.entries {
      let entry_path = current_path.join(component.as_str());

      if let Entry::Directory(subdir) = entry {
        let full_path = root.join(&entry_path);

        if subdir.entries.is_empty() {
          let relative_path =
            RelativePath::try_from(entry_path.as_path()).context(error::Path { path: &entry_path })?;
          ensure! {
            full_path.try_exists().context(error::FilesystemIo { path: &entry_path })?,
            error::MissingFile { path: relative_path },
          }

          let is_empty = std::fs::read_dir(full_path.as_std_path())
            .context(error::FilesystemIo { path: &entry_path })?
            .next()
            .is_none();

          if !is_empty {
            return Err(Error::EmptyDirectory {
              paths: vec![entry_path.into()],
            });
          }
        } else {
          Self::verify_empty_directories(root, &entry_path, subdir)?;
        }
      }
    }
    Ok(())
  }
}
