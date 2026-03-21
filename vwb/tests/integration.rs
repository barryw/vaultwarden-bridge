//! Integration tests for the vwb CLI binary.
//!
//! Expects a running bridge at TEST_BRIDGE_URL with seeded test data.
//! A machine key with glob policy "**" must exist, with its raw API key
//! in VWB_TEST_TOKEN.

use std::process::Command;

fn vwb_bin() -> String {
    // Cargo puts test binaries in target/debug or target/release
    // The vwb binary is a separate binary target
    let mut path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    path.push("vwb");
    path.to_string_lossy().to_string()
}

fn bridge_url() -> String {
    std::env::var("TEST_BRIDGE_URL").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string())
}

fn test_token() -> String {
    std::env::var("VWB_TEST_TOKEN").expect("VWB_TEST_TOKEN must be set for integration tests")
}

fn run_vwb(args: &[&str], addr: Option<&str>, token: Option<&str>) -> (i32, String, String) {
    let mut cmd = Command::new(vwb_bin());
    cmd.args(args);
    if let Some(a) = addr {
        cmd.env("VWB_ADDR", a);
    }
    if let Some(t) = token {
        cmd.env("VWB_TOKEN", t);
    }
    // Clear env vars we don't want leaking from parent
    if addr.is_none() {
        cmd.env_remove("VWB_ADDR");
    }
    if token.is_none() {
        cmd.env_remove("VWB_TOKEN");
    }

    let output = cmd.output().expect("failed to execute vwb");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

// --- Positive tests ---

#[test]
fn test_get_secret_success() {
    let (code, stdout, stderr) = run_vwb(
        &["get", "prod/db/password"],
        Some(&bridge_url()),
        Some(&test_token()),
    );
    assert_eq!(code, 0, "stderr: {}", stderr);
    assert_eq!(stdout, "super-secret-db-password");
    assert!(stderr.is_empty());
}

#[test]
fn test_get_different_secret() {
    let (code, stdout, _) = run_vwb(
        &["get", "staging/db/password"],
        Some(&bridge_url()),
        Some(&test_token()),
    );
    assert_eq!(code, 0);
    assert_eq!(stdout, "staging-db-password");
}

#[test]
fn test_no_trailing_newline() {
    let (_, stdout, _) = run_vwb(
        &["get", "prod/db/password"],
        Some(&bridge_url()),
        Some(&test_token()),
    );
    assert!(
        !stdout.ends_with('\n'),
        "stdout should not end with newline"
    );
}

// --- Negative tests: argument errors ---

#[test]
fn test_no_args() {
    let (code, _, stderr) = run_vwb(&[], Some(&bridge_url()), Some(&test_token()));
    assert_eq!(code, 1);
    assert!(stderr.contains("Usage"));
}

#[test]
fn test_wrong_subcommand() {
    let (code, _, stderr) = run_vwb(
        &["put", "something"],
        Some(&bridge_url()),
        Some(&test_token()),
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("Usage"));
}

#[test]
fn test_missing_key_arg() {
    let (code, _, stderr) = run_vwb(&["get"], Some(&bridge_url()), Some(&test_token()));
    assert_eq!(code, 1);
    assert!(stderr.contains("Usage"));
}

// --- Negative tests: missing env vars ---

#[test]
fn test_missing_addr() {
    let (code, _, stderr) = run_vwb(&["get", "prod/db/password"], None, Some("fake"));
    assert_eq!(code, 1);
    assert!(stderr.contains("VWB_ADDR"));
}

#[test]
fn test_missing_token() {
    let (code, _, stderr) = run_vwb(&["get", "prod/db/password"], Some(&bridge_url()), None);
    assert_eq!(code, 1);
    assert!(stderr.contains("VWB_TOKEN"));
}

// --- Negative tests: auth errors ---

#[test]
fn test_bad_token() {
    let (code, stdout, stderr) = run_vwb(
        &["get", "prod/db/password"],
        Some(&bridge_url()),
        Some("totally-invalid-token"),
    );
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(stderr.contains("unauthorized"));
}

// --- Negative tests: not found ---

#[test]
fn test_nonexistent_secret() {
    let (code, stdout, stderr) = run_vwb(
        &["get", "does/not/exist"],
        Some(&bridge_url()),
        Some(&test_token()),
    );
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(stderr.contains("not found"));
}

// --- Negative tests: network errors ---

#[test]
fn test_unreachable_server() {
    let (code, _, stderr) = run_vwb(
        &["get", "prod/db/password"],
        Some("http://127.0.0.1:1"),
        Some("fake"),
    );
    assert_eq!(code, 1);
    assert!(!stderr.is_empty());
}
