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

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 || args[1] != "get" {
        eprintln!("Usage: vwb get <key>");
        process::exit(1);
    }

    let key = &args[2];

    let addr = env::var("VWB_ADDR").unwrap_or_else(|_| {
        eprintln!("error: VWB_ADDR environment variable is not set");
        process::exit(1);
    });

    let token = env::var("VWB_TOKEN").unwrap_or_else(|_| {
        eprintln!("error: VWB_TOKEN environment variable is not set");
        process::exit(1);
    });

    let url = format!("{}/api/v1/secret/{}", addr.trim_end_matches('/'), key);

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("User-Agent", format!("vwb/{}", VERSION))
        .send();

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    };

    let status = resp.status();

    if status.is_success() {
        let body: SecretResponse = match resp.json() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: failed to parse response: {}", e);
                process::exit(1);
            }
        };
        print!("{}", body.value);
    } else {
        let msg = resp
            .json::<ErrorResponse>()
            .map(|e| e.error)
            .unwrap_or_else(|_| format!("HTTP {}", status));
        eprintln!("error: {}", msg);
        process::exit(1);
    }
}
