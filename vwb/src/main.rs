use std::env;
use std::process;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(serde::Deserialize)]
struct SecretResponse {
    value: String,
}

#[derive(serde::Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug)]
enum VwbError {
    Usage,
    MissingAddr,
    MissingToken,
    Request(String),
    Api(String),
}

impl std::fmt::Display for VwbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VwbError::Usage => write!(f, "Usage: vwb get <key>"),
            VwbError::MissingAddr => write!(f, "VWB_ADDR environment variable is not set"),
            VwbError::MissingToken => write!(f, "VWB_TOKEN environment variable is not set"),
            VwbError::Request(e) => write!(f, "{}", e),
            VwbError::Api(e) => write!(f, "{}", e),
        }
    }
}

fn build_client() -> Result<reqwest::blocking::Client, VwbError> {
    let mut builder = reqwest::blocking::Client::builder();

    if let Ok(ca_path) = env::var("VWB_CA_CERT") {
        let pem = std::fs::read(&ca_path)
            .map_err(|e| VwbError::Request(format!("failed to read CA cert {}: {}", ca_path, e)))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| VwbError::Request(format!("invalid CA cert: {}", e)))?;
        builder = builder.add_root_certificate(cert);
    }

    builder
        .build()
        .map_err(|e| VwbError::Request(e.to_string()))
}

fn fetch(addr: &str, token: &str, key: &str) -> Result<String, VwbError> {
    let url = format!("{}/api/v1/secret/{}", addr.trim_end_matches('/'), key);

    let client = build_client()?;
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("User-Agent", format!("vwb/{}", VERSION))
        .send()
        .map_err(|e| VwbError::Request(e.to_string()))?;

    let status = resp.status();

    if status.is_success() {
        let body: SecretResponse = resp
            .json()
            .map_err(|e| VwbError::Api(format!("failed to parse response: {}", e)))?;
        Ok(body.value)
    } else {
        let msg = resp
            .json::<ErrorResponse>()
            .map(|e| e.error)
            .unwrap_or_else(|_| format!("HTTP {}", status));
        Err(VwbError::Api(msg))
    }
}

fn run(args: &[String]) -> Result<String, VwbError> {
    if args.len() < 3 || args[1] != "get" {
        return Err(VwbError::Usage);
    }

    let key = &args[2];
    let addr = env::var("VWB_ADDR").map_err(|_| VwbError::MissingAddr)?;
    let token = env::var("VWB_TOKEN").map_err(|_| VwbError::MissingToken)?;

    fetch(&addr, &token, key)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match run(&args) {
        Ok(value) => print!("{}", value),
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_args_returns_usage() {
        let args = vec!["vwb".to_string()];
        let err = run(&args).unwrap_err();
        assert!(matches!(err, VwbError::Usage));
    }

    #[test]
    fn test_wrong_subcommand_returns_usage() {
        let args = vec!["vwb".to_string(), "put".to_string(), "key".to_string()];
        let err = run(&args).unwrap_err();
        assert!(matches!(err, VwbError::Usage));
    }

    #[test]
    fn test_missing_key_returns_usage() {
        let args = vec!["vwb".to_string(), "get".to_string()];
        let err = run(&args).unwrap_err();
        assert!(matches!(err, VwbError::Usage));
    }

    #[test]
    fn test_connection_refused() {
        let err = fetch("http://127.0.0.1:1", "fake", "key").unwrap_err();
        assert!(matches!(err, VwbError::Request(_)));
    }
}
