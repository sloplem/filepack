use super::*;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", transparent)]
pub(crate) struct Component(String);

impl Component {
  pub(crate) fn new(s: String) -> Self {
    Self(s)
  }

  pub(crate) fn as_bytes(&self) -> &[u8] {
    self.0.as_bytes()
  }

  pub(crate) fn as_str(&self) -> &str {
    &self.0
  }

  #[allow(dead_code)]
  pub(crate) fn len(&self) -> u64 {
    self.0.len().into_u64()
  }
}

impl From<&str> for Component {
  fn from(s: &str) -> Self {
    Self(s.to_owned())
  }
}

impl Display for Component {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    self.0.fmt(f)
  }
}
