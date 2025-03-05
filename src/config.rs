
static ABOUT: &str = "Recursive DNS resolver";

#[derive(Parser, Debug)]
#[command(version, about = ABOUT, long_about = None)]
pub struct Args {
  //
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
  #[serde(default)]
  pub admin: AdminConfig,
  #[serde(default)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminConfig {
  #[serde(default = "default_admin_port")]
  pub port: u16,
  #[serde(default = "default_admin_host")]
  pub host: String,
}

fn default_admin_port() -> u16 { 7778 }
fn default_admin_host() -> String { "0.0.0.0".to_string() }

impl Default for AdminConfig {
  fn default() -> Self {
    Self { port: default_admin_port(), host: default_admin_host() }
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolverConfig {
  pub port: u16,
  pub host: String,
}

fn default_resolver_port() -> u16 { 7777 }
fn default_resolver_host() -> String { "0.0.0.0".to_string() }

impl Default for ResolverConfig {
  fn default() -> Self {
    Self { port: default_resolver_port(), host: default_resolver_host() }
  }
}