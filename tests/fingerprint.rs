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

  let json = r#"{"files":{"foo":{"hash":"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262","size":0}}}"#;

  dir.child("filepack.json").assert(json.to_owned() + "\n");

  // Fingerprint is now calculated using recursive directory hashing, not JSON hashing
  let fingerprint = "8231b5a5dc0aaf84e9b5b67fc924d4d2cadb23ab91e3c3cfe9768e28516c0882";

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
