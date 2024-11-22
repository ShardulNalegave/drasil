
const ABOUT: &str = "Recursive DNS resolver";

#[derive(Debug, Parser, Serialize, Deserialize, Merge)]
#[command(version, about = ABOUT, long_about = None)]
pub struct Config {
  #[arg(short = 'p', long = "port", help = "Port to run the resolver on")]
  pub port: Option<u16>,
  #[arg(long = "host", help = "Host address to use")]
  pub host: Option<String>,
}

impl Default for Config {
  fn default() -> Self {
    Self { port: Some(7777), host: Some("0.0.0.0".to_string()) }
  }
}
