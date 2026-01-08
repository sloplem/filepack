use super::*;

#[derive(Parser)]
pub(crate) struct Create {
  #[arg(help = "Deny <LINT_GROUP>", long, value_name = "LINT_GROUP")]
  deny: Option<LintGroup>,
  #[arg(help = "Overwrite manifest if it already exists", long)]
  force: bool,
  #[arg(
    help = "Write manifest to <MANIFEST>, defaults to `<ROOT>/filepack.json`",
    long
  )]
  manifest: Option<Utf8PathBuf>,
  #[arg(help = "Include metadata from YAML document <METADATA>`", long)]
  metadata: Option<Utf8PathBuf>,
  #[arg(help = "Create manifest for files in <ROOT> directory, defaults to current directory")]
  root: Option<Utf8PathBuf>,
  #[arg(help = "Sign manifest with master key", long)]
  sign: bool,
}

impl Create {
  pub(crate) fn run(self, options: Options) -> Result {
    let current_dir = current_dir()?;

    let root = self.root.unwrap_or_else(|| current_dir.clone());

    let manifest_path = if let Some(path) = self.manifest {
      path
    } else {
      root.join(Manifest::FILENAME)
    };

    if let Some(path) = &self.metadata {
      let yaml = filesystem::read_to_string(path)?;
      let template = serde_yaml::from_str::<Template>(&yaml)
        .context(error::DeserializeMetadataTemplate { path })?;
      let path = root.join(Metadata::FILENAME);
      ensure! {
        self.force || !filesystem::exists(&path)?,
        error::MetadataAlreadyExists { path: &path },
      }
      Metadata::from(template).save(&path)?;
    }

    let cleaned_manifest = current_dir.join(&manifest_path).lexiclean();

    let cleaned_metadata = self.metadata.map(|path| current_dir.join(path).lexiclean());

    let mut paths = Vec::new();

    let mut case_conflicts = HashMap::<RelativePath, Vec<RelativePath>>::new();

    let mut lint_errors = 0u64;

    let mut directories = Directory::default();

    for entry in WalkDir::new(&root) {
      let entry = entry?;

      let path = entry.path();

      let path = decode_path(path)?;

      let cleaned_path = current_dir.join(path).lexiclean();

      if cleaned_path == cleaned_manifest {
        continue;
      }

      if cleaned_metadata
        .as_ref()
        .is_some_and(|path| cleaned_path == *path)
      {
        return Err(error::MetadataTemplateIncluded { path }.build());
      }

      ensure! {
        !entry.file_type().is_symlink(),
        error::Symlink { path },
      }

      let relative = if path == root {
        None
      } else {
        let relative = path.strip_prefix(&root).unwrap();
        Some(RelativePath::try_from(relative).context(error::Path { path: relative })?)
      };

      if let Some(relative) = relative.as_ref() {
        match self.deny {
          None => {}
          Some(LintGroup::All) => {
            if let Some(lint) = relative.lint() {
              eprintln!("error: path failed lint: `{relative}`");
              eprintln!("       └─ {lint}");
              lint_errors += 1;
            }

            case_conflicts
              .entry(relative.to_lowercase())
              .or_default()
              .push(relative.clone());
          }
        }
      }

      if entry.file_type().is_dir() {
        if let Some(relative) = relative {
          directories.insert_directory(&relative);
        }
        continue;
      }

      let relative = relative.expect("file entries are never root");

      let metadata = filesystem::metadata(path)?;

      paths.push((relative, metadata.len()));
    }

    for mut originals in case_conflicts.into_values() {
      if originals.len() > 1 {
        originals.sort();
        eprintln!("error: paths would conflict on case-insensitive filesystem:");
        for (i, original) in originals.iter().enumerate() {
          eprintln!(
            "       {}─ `{original}`",
            if i < originals.len() - 1 {
              '├'
            } else {
              '└'
            }
          );
        }
        lint_errors += 1;
      }
    }

    if lint_errors > 0 {
      return Err(error::Lint { count: lint_errors }.build());
    }

    ensure! {
      self.force || !manifest_path.try_exists().context(error::FilesystemIo { path: &manifest_path })?,
      error::ManifestAlreadyExists {
        path: manifest_path,
      },
    }

    let mut total_size = 0u64;

    for (_, size) in &paths {
      total_size += size;
    }

    let bar = progress_bar::new(&options, total_size);

    for (path, _size) in paths {
      let entry = options
        .hash_file(&root.join(&path))
        .context(error::FilesystemIo { path: &path })?;
      let size = entry.size;
      directories.insert_file(&path, entry);
      bar.inc(size);
    }

    let mut manifest = Manifest {
      files: directories,
      signatures: BTreeMap::new(),
    };

    if self.sign {
      let private_key_path = options.key_dir()?.join(MASTER_PRIVATE_KEY);

      let (public_key, signature) =
        PrivateKey::load_and_sign(&private_key_path, manifest.fingerprint().as_bytes())?;

      manifest.signatures.insert(public_key, signature);
    }

    manifest.save(&manifest_path)?;

    Ok(())
  }
}
