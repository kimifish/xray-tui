//! Render the real Outbounds UI and report using the isolated, credential-free demo.
use anyhow::Result;
use clap::Parser;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::PathBuf;
use xray_tui::{
    app::{self, App},
    service::{Options, Service},
};

fn main() -> Result<()> {
    let directory = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let service = Service::discover(&Options::parse_from(["xray-tui", "--demo"]))?;
    let mut app = App::new(app::demo_document(service.config.clone())?, service);
    app.key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
    app::snapshot(&mut app, &directory.join("health-outbounds.svg"))?;
    app.key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
    app::snapshot(&mut app, &directory.join("health-report.svg"))?;
    Ok(())
}
