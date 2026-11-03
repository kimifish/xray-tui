use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind},
    execute,
};
use std::io;
use xray_tui::{
    app::{self, App},
    config::Document,
    service::{Options, Service},
};

fn main() -> Result<()> {
    let options = Options::parse();
    let service = Service::discover(&options)?;
    if options.check_update {
        anyhow::ensure!(!options.demo, "Network actions disabled in demo mode");
        let release = xray_tui::update::latest()?;
        println!(
            "Installed: {}\nLatest: {}\nOfficial asset: {}",
            service.version()?,
            release.version,
            release.asset
        );
        return Ok(());
    }
    let doc = if options.demo {
        app::demo_document(service.config.clone())?
    } else {
        Document::load(&service.config)?
    };
    if options.probe.is_some() || options.probe_all {
        let settings = doc.meta.health.clone().unwrap_or_default();
        let mut success = true;
        let mut found = false;
        for entry in doc.entries("outbounds")? {
            let tag = entry.value["tag"].as_str().unwrap_or("untagged");
            if options.probe.as_deref() == Some(tag)
                || (options.probe_all
                    && entry.active_index.is_some()
                    && xray_tui::health::probeable(&entry))
            {
                found = true;
                let sample =
                    xray_tui::health::check(&doc, &entry, &settings, &service, options.extended)?;
                success &= sample.all_ok();
                println!("{}", serde_json::json!({"tag":tag,"sample":sample}));
            }
        }
        anyhow::ensure!(found, "No matching web outbounds");
        anyhow::ensure!(
            success,
            "Some outbound checks failed; see per-target results above"
        );
        return Ok(());
    }
    if options.check {
        service.test(&doc.rendered()?, None)?;
        println!("Config valid: {}", doc.path.display());
        return Ok(());
    }
    let mut app = App::new(doc, service);
    if let Some(path) = options.snapshot {
        app::snapshot(&mut app, &path)?;
        println!("Saved {}", path.display());
        return Ok(());
    }
    let mut terminal = ratatui::init();
    let result = (|| -> Result<()> {
        execute!(io::stdout(), EnableBracketedPaste)?;
        let mut redraw = true;
        while !app.quit {
            redraw |= app.poll();
            if redraw {
                terminal.draw(|f| app.draw(f))?;
                redraw = false;
            }
            if event::poll(app.poll_interval())? {
                match event::read()? {
                    Event::Key(key) if key.kind != KeyEventKind::Release => {
                        app.key(key);
                        redraw = true;
                    }
                    Event::Paste(text) => {
                        app.paste(&text);
                        redraw = true;
                    }
                    Event::Resize(..) => redraw = true,
                    _ => (),
                }
            }
        }
        Ok(())
    })();
    let _ = execute!(io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    result
}
