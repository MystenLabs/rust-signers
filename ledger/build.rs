fn main() {
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=LEDGER_SIGNER_VERSION={version}");

    let git_ref = std::env::var("GITHUB_REF_NAME").unwrap_or_else(|_| "local".to_string());
    println!("cargo:rustc-env=LEDGER_SIGNER_GIT_REF={git_ref}");

    let git_sha = std::env::var("GITHUB_SHA").unwrap_or_else(|_| "dev".to_string());
    let short_sha: String = git_sha.chars().take(7).collect();
    println!("cargo:rustc-env=LEDGER_SIGNER_GIT_SHA={short_sha}");
}
