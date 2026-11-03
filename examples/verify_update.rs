//! Exercise the official update download and candidate validation without installing it.
use anyhow::Result;
use clap::Parser;
use xray_tui::{
    service::{Options, Service},
    update,
};

fn main() -> Result<()> {
    let options = Options::parse();
    let service = Service::discover(&options)?;
    let release = update::latest()?;
    println!(
        "Downloading and validating {} ({})",
        release.version, release.asset
    );
    let prepared = update::prepare(&release, &service)?;
    println!(
        "Verified {}\nSHA-256: {}\nCandidate passed xray run -test. Nothing installed; service unchanged.",
        prepared.version, prepared.sha256
    );
    Ok(())
}
