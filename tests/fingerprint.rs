use super::*;

#[test]
fn fingerprint() {
  let dir = TempDir::new().unwrap();

  dir.child("foo").touch().unwrap();

  Command::cargo_bin("filepack")
    .unwrap()
    .arg("create")
    .current_dir(&dir)
    .assert()
    .success();

  dir.child("filepack.json").assert(manifest_json(|files| {
    files.insert_file(&"foo".parse().unwrap(), file_entry(b""));
  }));

  let (_path, manifest) = Manifest::load(Some(dir.child("filepack.json").utf8_path())).unwrap();
  let fingerprint = manifest.fingerprint().to_string();

  Command::cargo_bin("filepack")
    .unwrap()
    .arg("fingerprint")
    .current_dir(&dir)
    .assert()
    .stdout(format!("{fingerprint}\n"))
    .success();

  Command::cargo_bin("filepack")
    .unwrap()
    .args(["fingerprint", dir.path().to_str().unwrap()])
    .assert()
    .stdout(format!("{fingerprint}\n"))
    .success();

  Command::cargo_bin("filepack")
    .unwrap()
    .args([
      "fingerprint",
      dir.path().join("filepack.json").to_str().unwrap(),
    ])
    .assert()
    .stdout(format!("{fingerprint}\n"))
    .success();
}
