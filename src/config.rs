
static ABOUT: &str = "Recursive DNS resolver";

#[derive(Parser, Debug)]
#[command(version, about = ABOUT, long_about = None)]
pub struct Args {
  //
}

#[derive(Clone, Debug, Serialize, Deserialize, Merge)]
pub struct Config {
  pub admin: AdminConfig,
  pub resolver: ResolverConfig,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      admin: Default::default(),
      resolver: Default::default(),
    }
  }
}

#[derive(Clone, Debug, Serialize, Deserialize, Merge)]
pub struct AdminConfig {
  pub port: Option<u16>,
  pub host: Option<String>,
}

impl Default for AdminConfig {
  fn default() -> Self {
    Self { port: Some(7778), host: Some("0.0.0.0".to_string()) }
  }
}

#[derive(Clone, Debug, Serialize, Deserialize, Merge)]
pub struct ResolverConfig {
  pub port: Option<u16>,
  pub host: Option<String>,
}

impl Default for ResolverConfig {
  fn default() -> Self {
    Self { port: Some(7777), host: Some("0.0.0.0".to_string()) }
  }
}