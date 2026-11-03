use crate::{
    config::{self, Document, Entry, Subscription},
    health::{self, Monitor, Settings as HealthSettings, State as HealthState},
    import,
    service::{self, Service, Status},
    update::{self, PreparedUpdate, Release},
};
use anyhow::{Context, Result, ensure};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use serde_json::{Value, json};
use std::{
    process::Command,
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

const BG: Color = Color::Rgb(17, 22, 32);
const PANEL: Color = Color::Rgb(23, 30, 43);
const LINE: Color = Color::Rgb(48, 61, 80);
const TEXT: Color = Color::Rgb(212, 222, 237);
const MUTED: Color = Color::Rgb(133, 151, 176);
const CYAN: Color = Color::Rgb(99, 218, 211);
const GREEN: Color = Color::Rgb(151, 218, 166);
const YELLOW: Color = Color::Rgb(239, 198, 125);
const RED: Color = Color::Rgb(245, 142, 150);
const TABS: [&str; 7] = [
    "Overview",
    "Outbounds",
    "Routes",
    "Inbounds",
    "Subscriptions",
    "Config",
    "Logs",
];

#[derive(Clone)]
enum EditTarget {
    HealthSettings,
    Entry(String, Option<Entry>),
    Section(String),
    Full,
    Import,
    Route(Option<Entry>),
    Subscription(Option<usize>),
    Search,
}

struct Editor {
    title: String,
    text: String,
    cursor: usize,
    target: EditTarget,
    error: String,
}

struct Form {
    title: String,
    fields: Vec<(String, String)>,
    field: usize,
    cursor: usize,
    target: EditTarget,
    base: Value,
    error: String,
}

enum Action {
    Quit,
    Reload,
    Delete(String, Entry),
    Service(String),
    Save(bool),
    UseDraft(Box<Document>),
    Download(Release),
    Install(PreparedUpdate),
    ForgetSubscription(usize),
}

enum Modal {
    Report {
        title: String,
        body: String,
        scroll: u16,
    },
    Edit(Editor),
    Form(Form),
    Confirm {
        title: String,
        body: String,
        action: Box<Action>,
    },
    Help,
    Message(String, String),
}

enum Job {
    Message(String),
    Updated(String, String),
    Saved(String, String),
    Preview(Box<Document>, String),
    Release(Release),
    Prepared(PreparedUpdate),
    Logs(String),
    Error(String),
}

pub struct App {
    pub health: Monitor,
    pub doc: Document,
    pub service: Service,
    pub status: Status,
    tab: usize,
    selected: [usize; 7],
    filter: String,
    pub message: String,
    modal: Option<Modal>,
    job: Option<Receiver<Job>>,
    busy: String,
    status_job: Option<Receiver<Result<Status, String>>>,
    last_status: Instant,
    logs: String,
    scroll: u16,
    pub quit: bool,
    tick: usize,
    last_animation: Instant,
    last_health_display: Instant,
}

impl App {
    pub fn new(doc: Document, service: Service) -> Self {
        let mut status = service.status().unwrap_or_else(|_| Status {
            active: "unknown".into(),
            ..Status::default()
        });
        status.version = service
            .version()
            .unwrap_or_else(|_| "Version unavailable".into());
        Self {
            health: Monitor::new(&service),
            doc,
            service,
            status,
            tab: 0,
            selected: [0; 7],
            filter: String::new(),
            message: "Ready · changes stay in a draft until you save".into(),
            modal: None,
            job: None,
            busy: String::new(),
            status_job: None,
            last_status: Instant::now(),
            logs: String::new(),
            scroll: 0,
            quit: false,
            tick: 0,
            last_animation: Instant::now(),
            last_health_display: Instant::now(),
        }
    }

    fn start_job(&mut self, title: &str, work: impl FnOnce() -> Result<Job> + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let result = work().unwrap_or_else(|e| Job::Error(format!("{e:#}")));
            let _ = tx.send(result);
        });
        self.job = Some(rx);
        self.busy = title.into();
    }

    /// Return true only when there is something new to display.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        if self.job.is_some() && self.last_animation.elapsed() >= Duration::from_millis(240) {
            self.tick = self.tick.wrapping_add(3);
            self.last_animation = Instant::now();
            changed = true;
        }
        let settings = self.health_settings();
        changed |= self.health.tick(
            &self.service,
            &settings,
            self.job.is_none() && self.status.active == "active",
        );
        let display_due = self.last_health_display.elapsed() >= Duration::from_secs(1);
        if display_due || changed {
            if matches!(self.modal, Some(Modal::Report { .. })) {
                let report = self.current().map(|entry| {
                    self.health
                        .report(&self.doc, &entry, &settings, &self.service)
                });
                if let (Some(report), Some(Modal::Report { body, .. })) = (report, &mut self.modal)
                    && *body != report
                {
                    *body = report;
                    changed = true;
                }
            }
            // Result ages and stale indicators change with time even without new probes.
            if display_due {
                self.last_health_display = Instant::now();
                changed |= self.tab == 1 && self.health.has_results();
            }
        }
        if let Some(rx) = &self.job {
            match rx.try_recv() {
                Ok(result) => {
                    changed = true;
                    self.job = None;
                    self.busy.clear();
                    match result {
                        Job::Message(s) => { self.message = s; self.last_status = Instant::now() - Duration::from_secs(10); },
                        Job::Updated(message,version) => {self.message=message;self.status.version=version;self.last_status=Instant::now()-Duration::from_secs(10);},
                        Job::Saved(text,s) => {
                            self.doc.original = text.clone();
                            self.doc.text = text;
                            self.message = s;
                            self.last_status = Instant::now() - Duration::from_secs(10);
                        },
                        Job::Preview(doc,summary) => self.confirm("Subscription preview",format!("{summary}\n\nAccept these changes into the draft?\nSave/apply remains a separate action."),Action::UseDraft(doc)),
                        Job::Release(release) => self.confirm("Official Xray update",format!("Installed: {}\nLatest stable: {}\nAsset: {}\nSource: github.com/XTLS/Xray-core\n\nDownload, verify SHA-256 and test this release?\nInstallation requires another confirmation.",self.status.version,release.version,release.asset),Action::Download(release)),
                        Job::Prepared(update) => self.confirm("Install verified release",format!("Version: {}\nArchive SHA-256:\n{}\n\nThe candidate passed xray run -test.\nReplace {} and restart if active?\nThe old binary will be backed up.",update.version,update.sha256,self.service.binary.display()),Action::Install(update)),
                        Job::Logs(s) => { self.logs = s; self.scroll = 0; self.message = "Journal refreshed".into(); },
                        Job::Error(s) => self.modal = Some(Modal::Message("Operation failed".into(),s)),
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    changed = true;
                    self.job = None;
                    self.busy.clear();
                    self.message = "Background operation ended unexpectedly".into();
                }
                _ => (),
            }
        }
        if let Some(rx) = &self.status_job {
            match rx.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(mut status) => {
                            status.version = self.status.version.clone();
                            changed |= self.status != status;
                            self.status = status;
                        }
                        Err(_) => {
                            changed |=
                                self.status.active != "unknown" || self.status.sub != "unavailable";
                            self.status.active = "unknown".into();
                            self.status.sub = "unavailable".into();
                        }
                    }
                    self.status_job = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.status_job = None,
                _ => (),
            }
        }
        if self.last_status.elapsed() >= Duration::from_secs(4)
            && self.status_job.is_none()
            && self.job.is_none()
        {
            let s = self.service.clone();
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let _ = tx.send(s.status().map_err(|e| e.to_string()));
            });
            self.status_job = Some(rx);
            self.last_status = Instant::now();
        }
        changed
    }

    pub fn poll_interval(&self) -> Duration {
        if self.job.is_some() || self.status_job.is_some() || self.health.counts().0 > 0 {
            Duration::from_millis(80)
        } else {
            Duration::from_millis(250)
        }
    }

    fn confirm(&mut self, title: &str, body: String, action: Action) {
        self.modal = Some(Modal::Confirm {
            title: title.into(),
            body,
            action: Box::new(action),
        });
    }

    fn health_settings(&self) -> HealthSettings {
        self.doc.meta.health.clone().unwrap_or_default()
    }

    fn probe_selected(&mut self, extended: bool) -> Result<()> {
        let entry = self.current().context("Select an outbound first")?;
        let settings = self.health_settings();
        let queued = self
            .health
            .enqueue(&self.doc, &entry, &settings, &self.service, extended)?;
        self.message = if queued {
            format!(
                "{} probe queued · {} · h details",
                if extended { "Extended" } else { "HTTPS" },
                health::origin(&self.doc, &entry).label()
            )
        } else {
            "Probe already queued/running".into()
        };
        Ok(())
    }

    fn section(&self) -> Option<&'static str> {
        match self.tab {
            1 => Some("outbounds"),
            2 => Some("rules"),
            3 => Some("inbounds"),
            _ => None,
        }
    }

    fn entries(&self) -> Vec<Entry> {
        self.section()
            .and_then(|s| self.doc.entries(s).ok())
            .unwrap_or_default()
            .into_iter()
            .filter(|e| {
                self.filter.is_empty()
                    || config::redacted(e.value.clone())
                        .to_string()
                        .to_lowercase()
                        .contains(&self.filter.to_lowercase())
            })
            .collect()
    }

    fn current(&self) -> Option<Entry> {
        self.entries().get(self.selected[self.tab]).cloned()
    }

    fn keys(&self) -> Vec<String> {
        self.doc
            .value()
            .ok()
            .and_then(|v| v.as_object().map(|o| o.keys().cloned().collect()))
            .unwrap_or_default()
    }

    fn count(&self) -> usize {
        match self.tab {
            1..=3 => self.entries().len(),
            4 => self.doc.meta.subscriptions.len(),
            5 => self.keys().len(),
            _ => 1,
        }
    }

    fn editor(&mut self, title: &str, text: String, target: EditTarget) {
        self.modal = Some(Modal::Edit(Editor {
            title: title.into(),
            text,
            cursor: 0,
            target,
            error: String::new(),
        }));
    }

    fn route_form(&mut self, entry: Option<Entry>) {
        let v = entry
            .as_ref()
            .map(|e| e.value.clone())
            .unwrap_or(json!({"type":"field"}));
        let list = |key: &str| {
            v[key]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        };
        let fields = vec![
            (
                "Name / ruleTag".into(),
                v["ruleTag"].as_str().unwrap_or("").into(),
            ),
            (
                "Outbound tag (F2 cycles active connections)".into(),
                v["outboundTag"].as_str().unwrap_or("").into(),
            ),
            ("Domains (comma separated)".into(), list("domain")),
            ("IPs / CIDRs / geoip (comma separated)".into(), list("ip")),
            (
                "Ports (e.g. 80,443,1000-2000)".into(),
                v["port"]
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| v["port"].as_u64().map(|n| n.to_string()))
                    .unwrap_or_default(),
            ),
            (
                "Network (tcp / udp / tcp,udp)".into(),
                v["network"].as_str().unwrap_or("").into(),
            ),
            ("Inbound tags (comma separated)".into(), list("inboundTag")),
            ("Protocols (http,tls,bittorrent)".into(), list("protocol")),
        ];
        self.modal = Some(Modal::Form(Form {
            title: "Route · filters match together; rules run top to bottom".into(),
            fields,
            field: 0,
            cursor: 0,
            target: EditTarget::Route(entry),
            base: v,
            error: String::new(),
        }));
    }

    fn subscription_form(&mut self, index: Option<usize>) {
        let sub = index.and_then(|i| self.doc.meta.subscriptions.get(i));
        self.modal = Some(Modal::Form(Form {
            title: "Subscription · HTTPS URL, kept privately in config comments".into(),
            fields: vec![
                (
                    "Name".into(),
                    sub.map(|s| s.name.clone()).unwrap_or_default(),
                ),
                (
                    "URL (may contain a private token)".into(),
                    sub.map(|s| s.url.clone()).unwrap_or_default(),
                ),
            ],
            field: 0,
            cursor: 0,
            target: EditTarget::Subscription(index),
            base: Value::Null,
            error: String::new(),
        }));
    }

    fn fetch_subscriptions(&mut self, all: bool) -> Result<()> {
        ensure!(
            !self.service.demo,
            "Network actions are disabled in demo mode"
        );
        let subscriptions = if all {
            self.doc.meta.subscriptions.clone()
        } else {
            vec![
                self.doc
                    .meta
                    .subscriptions
                    .get(self.selected[4])
                    .context("Add a subscription with 'n' first")?
                    .clone(),
            ]
        };
        ensure!(!subscriptions.is_empty(), "No subscriptions");
        let mut doc = self.doc.clone();
        self.start_job("Fetching subscription · preview follows", move || {
            let mut lines = Vec::new();
            for sub in subscriptions {
                let nodes = import::fetch_subscription(&sub.url).with_context(|| {
                    format!("Subscription '{}' could not be imported", sub.name)
                })?;
                let name = sub.name.clone();
                let (updated, message) = import::merge_subscription(&doc, sub, &nodes)?;
                doc = updated;
                lines.push(format!("{name}: {message}"));
                lines.extend(
                    nodes
                        .iter()
                        .take(6)
                        .map(|n| format!("  + {} · {}", strv(n, "tag"), strv(n, "protocol"))),
                );
            }
            Ok(Job::Preview(Box::new(doc), lines.join("\n")))
        });
        Ok(())
    }

    pub fn paste(&mut self, text: &str) {
        match &mut self.modal {
            Some(Modal::Edit(e)) => {
                e.text.insert_str(e.cursor, text);
                e.cursor += text.len();
            }
            Some(Modal::Form(f)) => {
                let text = text.replace(['\n', '\r'], "");
                f.fields[f.field].1.insert_str(f.cursor, &text);
                f.cursor += text.len();
            }
            _ => (),
        }
    }

    pub fn key(&mut self, key: KeyEvent) {
        if let Err(error) = self.handle_key(key) {
            self.modal = Some(Modal::Message(
                "Cannot complete action".into(),
                format!("{error:#}"),
            ));
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<()> {
        if self.modal.is_some() {
            return self.modal_key(key);
        }
        if self.tab == 1 {
            match key.code {
                KeyCode::Char('t') => {
                    self.probe_selected(key.modifiers.contains(KeyModifiers::CONTROL))?;
                    return Ok(());
                }
                KeyCode::Char('T') => {
                    let settings = self.health_settings();
                    let mut count = 0;
                    for entry in self
                        .doc
                        .entries("outbounds")?
                        .into_iter()
                        .filter(|e| e.active_index.is_some() && health::probeable(e))
                    {
                        if self.health.enqueue(
                            &self.doc,
                            &entry,
                            &settings,
                            &self.service,
                            false,
                        )? {
                            count += 1;
                        }
                    }
                    self.message =
                        format!("{count} outbound probes queued · editing remains available");
                    return Ok(());
                }
                KeyCode::Char('p') => {
                    let mut settings = self.health_settings();
                    settings.enabled = !settings.enabled;
                    if !settings.enabled {
                        self.health.pause_periodic();
                    }
                    self.message = format!(
                        "Automatic health checks {} · w saves this preference",
                        if settings.enabled { "ON" } else { "PAUSED" }
                    );
                    self.doc.meta.health = Some(settings);
                    return Ok(());
                }
                KeyCode::Char('h') => {
                    let entry = self.current().context("Select an outbound first")?;
                    self.modal = Some(Modal::Report {
                        title: "Outbound health · HTTPS through isolated Xray".into(),
                        body: self.health.report(
                            &self.doc,
                            &entry,
                            &self.health_settings(),
                            &self.service,
                        ),
                        scroll: 0,
                    });
                    return Ok(());
                }
                KeyCode::Char('H') => {
                    self.editor(
                        "Health settings · HTTPS targets, interval, timeouts",
                        serde_json::to_string_pretty(&self.health_settings())?,
                        EditTarget::HealthSettings,
                    );
                    return Ok(());
                }
                _ => (),
            }
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            if self.job.is_some() {
                self.message = "An operation is running; wait for its result before exiting".into();
            } else {
                self.request_quit();
            }
            return Ok(());
        }
        match key.code {
            KeyCode::Char('?') | KeyCode::F(1) => {
                self.modal = Some(Modal::Help);
                return Ok(());
            }
            KeyCode::Tab | KeyCode::Right => {
                self.tab = (self.tab + 1) % 7;
                self.filter.clear();
                self.scroll = 0;
                return Ok(());
            }
            KeyCode::BackTab | KeyCode::Left => {
                self.tab = (self.tab + 6) % 7;
                self.filter.clear();
                self.scroll = 0;
                return Ok(());
            }
            KeyCode::Char(c @ '1'..='7') => {
                self.tab = (c as u8 - b'1') as usize;
                self.filter.clear();
                self.scroll = 0;
                return Ok(());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.tab == 6 {
                    self.scroll = self.scroll.saturating_add(1);
                } else {
                    self.selected[self.tab] =
                        (self.selected[self.tab] + 1).min(self.count().saturating_sub(1));
                    self.scroll = 0;
                }
                return Ok(());
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.tab == 6 {
                    self.scroll = self.scroll.saturating_sub(1);
                } else {
                    self.selected[self.tab] = self.selected[self.tab].saturating_sub(1);
                    self.scroll = 0;
                }
                return Ok(());
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(12);
                return Ok(());
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(12);
                return Ok(());
            }
            KeyCode::Esc => {
                self.filter.clear();
                return Ok(());
            }
            _ => (),
        }
        if self.job.is_some() {
            self.message = format!("{} · please wait", self.busy);
            return Ok(());
        }
        match key.code {
            KeyCode::Char('q') => self.request_quit(),
            KeyCode::Char('/') if self.section().is_some() => self.editor("Filter list",self.filter.clone(),EditTarget::Search),
            KeyCode::Char('s') => self.confirm("Start Xray",format!("Start {} using the saved config?",self.service.unit),Action::Service("start".into())),
            KeyCode::Char('x') => self.confirm("Stop Xray","Active proxy connections will be interrupted. Stop the service?".into(),Action::Service("stop".into())),
            KeyCode::Char('r') if self.tab != 6 => self.confirm("Restart Xray","Restart using the saved config? Active connections will reconnect; unsaved draft changes are excluded.".into(),Action::Service("restart".into())),
            KeyCode::Char('w') => self.confirm("Save config",format!("Validate and save draft to {}?\nA private backup is created. The service keeps running with its existing settings until restarted.",self.doc.path.display()),Action::Save(false)),
            KeyCode::Char('a') => self.confirm("Apply draft",format!("Validate, save and restart {}?\nOn startup failure the previous config is restored.",self.service.unit),Action::Save(true)),
            KeyCode::Char('v') => { self.doc.validate_structure()?; let s=self.service.clone(); let text=self.doc.rendered()?; self.start_job("Validating draft with Xray",move || { s.test(&text,None)?; Ok(Job::Message("Draft passed xray run -test; no files changed".into())) }); },
            KeyCode::Char('R') => self.confirm("Reload config", "Discard the draft and reload config from disk?".into(),Action::Reload),
            KeyCode::Char('u') if self.tab == 4 => self.fetch_subscriptions(false)?,
            KeyCode::Char('U') if self.tab == 4 => self.fetch_subscriptions(true)?,
            KeyCode::Char('u') => { ensure!(!self.service.demo,"Network actions disabled in demo mode"); ensure!(!self.doc.dirty(),"Save or discard the draft before updating the core"); self.start_job("Checking official GitHub release",move || Ok(Job::Release(update::latest()?))); },
            KeyCode::Char('i') => self.editor("Import outbound · paste JSONC, share links, or base64 subscription",String::new(),EditTarget::Import),
            KeyCode::Char('n') => match self.tab {
                1 => self.editor("New outbound · JSON or share link",String::new(),EditTarget::Import),
                2 => self.route_form(None),
                3 => self.editor("New inbound",serde_json::to_string_pretty(&json!({"tag":"local-socks","listen":"127.0.0.1","port":10810,"protocol":"socks","settings":{"auth":"noauth","udp":true}}))?,EditTarget::Entry("inbounds".into(),None)),
                4 => self.subscription_form(None),
                _ => (),
            },
            KeyCode::Enter if self.tab == 2 => { let e=self.current(); if e.is_some() { self.route_form(e); } },
            KeyCode::Enter if self.tab == 4 => { if !self.doc.meta.subscriptions.is_empty() { self.subscription_form(Some(self.selected[4])); } },
            KeyCode::Enter | KeyCode::Char('e') => {
                if let Some(section)=self.section() {
                    if let Some(entry)=self.current() { self.editor("Edit JSONC · credentials are visible while editing",entry.raw.clone(),EditTarget::Entry(section.into(),Some(entry))); }
                } else if self.tab == 5 && let Some(key)=self.keys().get(self.selected[5]) {
                    let text=self.doc.section_raw(key)?;
                    self.editor(&format!("Edit {key}"),text,EditTarget::Section(key.clone()));
                }
            },
            KeyCode::Char('E') => self.editor("Edit full config.jsonc · Ctrl-S accepts draft",self.doc.rendered()?,EditTarget::Full),
            KeyCode::Char(' ') => {
                if let (Some(section),Some(entry))=(self.section(),self.current()) {
                    self.doc.toggle(section,&entry)?; self.message="Toggled in draft · save/apply when ready".into();
                }
            },
            KeyCode::Char('d') if self.tab == 1 => {
                let e=self.current().context("Select an outbound")?;
                self.doc.move_entry("outbounds",e.active_index.context("Enable this outbound first")?,0)?;
                self.selected[1]=0; self.message="Default outbound changed in draft".into();
            },
            KeyCode::Char('J') | KeyCode::Char('K') if self.section().is_some() => {
                ensure!(self.filter.is_empty(),"Clear the filter before reordering");
                let section=self.section().unwrap(); let entry=self.current().context("Select an entry")?;
                let from=entry.active_index.context("Enable this entry before reordering")?;
                let to=if key.code==KeyCode::Char('J') {from+1} else {from.checked_sub(1).context("Already at the top")?};
                self.doc.move_entry(section,from,to)?; self.selected[self.tab]=to; self.message="Priority changed in draft".into();
            },
            KeyCode::Delete => {
                if let (Some(section),Some(entry))=(self.section(),self.current()) { self.confirm("Delete entry",format!("Remove {} from the draft?",entry_title(&entry,self.tab)),Action::Delete(section.into(),entry)); }
                else if self.tab==4 && !self.doc.meta.subscriptions.is_empty() { self.confirm("Forget subscription","Remove subscription metadata? Imported outbounds are kept as manual nodes.".into(),Action::ForgetSubscription(self.selected[4])); }
            },
            KeyCode::Char('r') | KeyCode::Char('l') if self.tab==6 => self.refresh_logs(),
            _ => (),
        }
        Ok(())
    }

    fn request_quit(&mut self) {
        if self.doc.dirty() {
            self.confirm(
                "Unsaved draft",
                "Discard unsaved changes and quit?".into(),
                Action::Quit,
            );
        } else {
            self.quit = true;
        }
    }

    fn refresh_logs(&mut self) {
        if self.service.demo {
            self.logs="2026-11-01 14:39:10 Xray started\n2026-11-01 14:39:10 Configuration loaded successfully\n2026-11-01 14:39:10 SOCKS listener ready at 127.0.0.1:10808".into();
            return;
        }
        let s = self.service.clone();
        self.start_job("Reading systemd journal", move || {
            let mut c = Command::new("journalctl");
            if s.user {
                c.arg("--user");
            }
            let text = service::run(
                c.args(["-u", &s.unit, "-n", "200", "--no-pager", "-o", "short-iso"]),
                Duration::from_secs(10),
            )?;
            Ok(Job::Logs(text))
        });
    }

    fn modal_key(&mut self, key: KeyEvent) -> Result<()> {
        let Some(mut modal) = self.modal.take() else {
            return Ok(());
        };
        if key.code == KeyCode::Esc {
            return Ok(());
        }
        match &mut modal {
            Modal::Report { body, scroll, .. } => match key.code {
                KeyCode::Enter | KeyCode::Char('q') => return Ok(()),
                KeyCode::Down | KeyCode::Char('j') => {
                    *scroll = scroll
                        .saturating_add(1)
                        .min(body.lines().count().saturating_sub(1) as u16)
                }
                KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                KeyCode::PageDown => {
                    *scroll = scroll
                        .saturating_add(10)
                        .min(body.lines().count().saturating_sub(1) as u16)
                }
                KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                _ => (),
            },
            Modal::Help | Modal::Message(_, _) => {
                if matches!(key.code, KeyCode::Enter | KeyCode::Char('q')) {
                    return Ok(());
                }
            }
            Modal::Confirm { .. } => {
                if key.code == KeyCode::Char('n') {
                    return Ok(());
                }
                if key.code == KeyCode::Char('y') {
                    if let Modal::Confirm { action, .. } = modal {
                        self.execute(*action)?;
                    }
                    return Ok(());
                }
            }
            Modal::Edit(e) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s')
                    || matches!(e.target, EditTarget::Search) && key.code == KeyCode::Enter
                {
                    match self.accept_editor(e) {
                        Ok(()) => return Ok(()),
                        Err(error) => e.error = format!("{error:#}"),
                    }
                } else {
                    edit_key(e, key);
                }
            }
            Modal::Form(f) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
                    match self.accept_form(f) {
                        Ok(()) => return Ok(()),
                        Err(error) => f.error = format!("{error:#}"),
                    }
                } else {
                    match key.code {
                        KeyCode::Tab | KeyCode::Down | KeyCode::Enter => {
                            f.field = (f.field + 1) % f.fields.len();
                            f.cursor = f.fields[f.field].1.len();
                        }
                        KeyCode::BackTab | KeyCode::Up => {
                            f.field = (f.field + f.fields.len() - 1) % f.fields.len();
                            f.cursor = f.fields[f.field].1.len();
                        }
                        KeyCode::F(2)
                            if matches!(f.target, EditTarget::Route(_)) && f.field == 1 =>
                        {
                            let tags: Vec<_> = self
                                .doc
                                .entries("outbounds")?
                                .into_iter()
                                .filter(|e| e.active_index.is_some())
                                .filter_map(|e| e.value["tag"].as_str().map(str::to_owned))
                                .collect();
                            if !tags.is_empty() {
                                let next = tags
                                    .iter()
                                    .position(|s| *s == f.fields[1].1)
                                    .map(|i| (i + 1) % tags.len())
                                    .unwrap_or(0);
                                f.fields[1].1 = tags[next].clone();
                                f.cursor = f.fields[1].1.len();
                            }
                        }
                        _ => {
                            let mut editor = Editor {
                                title: String::new(),
                                text: std::mem::take(&mut f.fields[f.field].1),
                                cursor: f.cursor,
                                target: EditTarget::Search,
                                error: String::new(),
                            };
                            edit_key(&mut editor, key);
                            f.fields[f.field].1 = editor.text;
                            f.cursor = editor.cursor;
                        }
                    }
                }
            }
        }
        // accept_editor may replace the modal with a preview.
        if self.modal.is_none() {
            self.modal = Some(modal);
        }
        Ok(())
    }

    fn accept_editor(&mut self, e: &Editor) -> Result<()> {
        match &e.target {
            EditTarget::HealthSettings => {
                let settings: HealthSettings =
                    serde_json::from_value(crate::config::parse(&e.text)?)?;
                settings.validate()?;
                if !settings.enabled {
                    self.health.pause_periodic();
                }
                self.doc.meta.health = Some(settings);
            }
            EditTarget::Entry(section, entry) => {
                self.doc.put_raw(section, entry.as_ref(), &e.text)?
            }
            EditTarget::Section(key) => self.doc.set_section_raw(key, &e.text)?,
            EditTarget::Full => self.doc.replace_text(e.text.clone())?,
            EditTarget::Search => {
                self.filter = e.text.clone();
                self.selected[self.tab] = 0;
                return Ok(());
            }
            EditTarget::Import => {
                let nodes = import::parse_nodes(&e.text)?;
                let mut draft = self.doc.clone();
                for (i, node) in nodes.iter().enumerate() {
                    let mut node = node.clone();
                    if node["tag"].as_str().is_none_or(str::is_empty) {
                        node["tag"] = json!(format!("import-{}", i + 1));
                    }
                    draft.put("outbounds", None, &serde_json::to_string_pretty(&node)?)?;
                }
                let names = nodes
                    .iter()
                    .take(12)
                    .map(|n| format!("+ {} · {}", strv(n, "tag"), strv(n, "protocol")))
                    .collect::<Vec<_>>()
                    .join("\n");
                self.confirm(
                    "Import preview",
                    format!(
                        "{} outbound(s)\n{names}\n\nAdd these nodes to the draft?",
                        nodes.len()
                    ),
                    Action::UseDraft(Box::new(draft)),
                );
                return Ok(());
            }
            _ => (),
        }
        self.message = "Draft updated · w save · a apply".into();
        Ok(())
    }

    fn accept_form(&mut self, f: &Form) -> Result<()> {
        match &f.target {
            EditTarget::Route(entry) => {
                let mut value = f.base.clone();
                let tag = f.fields[1].1.trim();
                ensure!(!tag.is_empty(), "Select an outbound tag");
                ensure!(
                    self.doc
                        .entries("outbounds")?
                        .iter()
                        .any(|e| e.active_index.is_some() && e.value["tag"].as_str() == Some(tag)),
                    "No active outbound with tag '{tag}'"
                );
                value["type"] = json!("field");
                value["outboundTag"] = json!(tag);
                value.as_object_mut().unwrap().remove("balancerTag");
                for (i, key) in [(0, "ruleTag"), (4, "port"), (5, "network")] {
                    let text = f.fields[i].1.trim();
                    if text.is_empty() {
                        value.as_object_mut().unwrap().remove(key);
                    } else {
                        value[key] = json!(text);
                    }
                }
                for (i, key) in [(2, "domain"), (3, "ip"), (6, "inboundTag"), (7, "protocol")] {
                    let parts: Vec<_> = f.fields[i]
                        .1
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .collect();
                    if parts.is_empty() {
                        value.as_object_mut().unwrap().remove(key);
                    } else {
                        value[key] = json!(parts);
                    }
                }
                ensure!(
                    value.as_object().unwrap().keys().any(|k| ![
                        "type",
                        "ruleTag",
                        "outboundTag",
                        "balancerTag"
                    ]
                    .contains(&k.as_str())),
                    "Add at least one route filter"
                );
                self.doc.put(
                    "rules",
                    entry.as_ref(),
                    &serde_json::to_string_pretty(&value)?,
                )?;
            }
            EditTarget::Subscription(index) => {
                let name = f.fields[0].1.trim();
                let url = f.fields[1].1.trim();
                ensure!(!name.is_empty(), "Name is required");
                ensure!(
                    !self
                        .doc
                        .meta
                        .subscriptions
                        .iter()
                        .enumerate()
                        .any(|(i, s)| Some(i) != *index && s.name == name),
                    "Subscription name already exists"
                );
                let parsed = url::Url::parse(url).context("Invalid URL")?;
                ensure!(
                    parsed.scheme() == "https" && parsed.host_str().is_some(),
                    "Use an HTTPS subscription URL"
                );
                if let Some(i) = index {
                    let old = &mut self.doc.meta.subscriptions[*i];
                    ensure!(
                        old.name == name || old.tags.is_empty(),
                        "A populated subscription cannot be renamed; its name prefixes imported tags"
                    );
                    old.name = name.into();
                    old.url = url.into();
                } else {
                    self.doc.meta.subscriptions.push(Subscription {
                        name: name.into(),
                        url: url.into(),
                        tags: vec![],
                        updated: None,
                    });
                }
                self.message = "Subscription saved in draft · press u to fetch a preview".into();
                return Ok(());
            }
            _ => (),
        }
        self.message = "Route updated in draft".into();
        Ok(())
    }

    fn execute(&mut self, action: Action) -> Result<()> {
        match action {
            Action::Quit => self.quit = true,
            Action::Reload => {
                self.doc = Document::load(&self.doc.path)?;
                self.selected = [0; 7];
                self.message = "Reloaded from disk".into();
            }
            Action::UseDraft(doc) => {
                self.doc = *doc;
                self.message = "Preview accepted into draft · w save · a apply".into();
            }
            Action::Delete(section, entry) => {
                self.doc.delete(&section, &entry)?;
                self.selected[self.tab] =
                    self.selected[self.tab].min(self.count().saturating_sub(1));
                self.message = "Removed from draft".into();
            }
            Action::ForgetSubscription(i) => {
                self.doc.meta.subscriptions.remove(i);
                self.selected[4] = self.selected[4].min(self.count().saturating_sub(1));
            }
            Action::Service(action) => {
                let s = self.service.clone();
                self.start_job("Updating systemd service", move || {
                    if action != "stop" {
                        s.test(&std::fs::read_to_string(&s.config)?, None)?;
                    }
                    Ok(Job::Message(s.action(&action)?))
                });
            }
            Action::Save(apply) => {
                let s = self.service.clone();
                let d = self.doc.clone();
                self.start_job(
                    if apply {
                        "Validating, saving and applying"
                    } else {
                        "Validating and saving"
                    },
                    move || {
                        let (text, message) = s.save(&d, apply)?;
                        Ok(Job::Saved(text, message))
                    },
                );
            }
            Action::Download(release) => {
                let s = self.service.clone();
                self.start_job(
                    "Downloading official archive · checking SHA-256",
                    move || Ok(Job::Prepared(update::prepare(&release, &s)?)),
                );
            }
            Action::Install(prepared) => {
                let s = self.service.clone();
                self.start_job("Installing verified Xray release", move || {
                    let message = update::install(prepared, &s)?;
                    Ok(Job::Updated(
                        message,
                        s.version().unwrap_or_else(|_| "Version unavailable".into()),
                    ))
                });
            }
        }
        Ok(())
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();
        frame.render_widget(
            Block::default().style(Style::default().bg(BG).fg(TEXT)),
            area,
        );
        if area.width < 76 || area.height < 22 {
            frame.render_widget(
                Paragraph::new("Window too small · resize to at least 76 × 22\nq to quit")
                    .style(Style::default().fg(YELLOW))
                    .block(panel(" Xray TUI ")),
                area,
            );
            return;
        }
        let outer = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .margin(1)
        .split(area);
        let state = if self.doc.dirty() {
            "● DRAFT"
        } else {
            "✓ SAVED"
        };
        let header = Line::from(vec![
            Span::styled(" ◈  XRAY ", Style::default().fg(CYAN).bold()),
            Span::styled(" / control room", Style::default().fg(MUTED)),
            Span::raw("     "),
            Span::styled(
                format!("● {}", self.status.active),
                Style::default().fg(if self.status.active == "active" {
                    GREEN
                } else {
                    YELLOW
                }),
            ),
            Span::raw("    "),
            Span::styled(
                state,
                Style::default().fg(if self.doc.dirty() { YELLOW } else { MUTED }),
            ),
            Span::styled(
                if self.service.demo {
                    "    DEMO · isolated"
                } else {
                    "    LOCAL · systemd"
                },
                Style::default().fg(MUTED),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(header).block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(Style::default().fg(LINE)),
            ),
            outer[0],
        );
        let columns = Layout::horizontal([Constraint::Length(23), Constraint::Min(1)])
            .spacing(2)
            .split(outer[1]);
        self.draw_nav(frame, columns[0]);
        match self.tab {
            0 => self.draw_overview(frame, columns[1]),
            1..=3 => self.draw_entries(frame, columns[1]),
            4 => self.draw_subscriptions(frame, columns[1]),
            5 => self.draw_config(frame, columns[1]),
            6 => {
                frame.render_widget(
                    Paragraph::new(if self.logs.is_empty() {
                        "Press l to load the systemd journal"
                    } else {
                        &self.logs
                    })
                    .scroll((self.scroll, 0))
                    .style(Style::default().fg(MUTED))
                    .block(panel(" Journal · l refresh · PgUp/PgDn scroll "))
                    .wrap(Wrap { trim: false }),
                    columns[1],
                );
            }
            _ => (),
        }
        let mut status = if self.job.is_some() {
            format!(
                "{} {}",
                ["◐", "◓", "◑", "◒"][(self.tick / 3) % 4],
                self.busy
            )
        } else {
            self.message.clone()
        };
        let (checking, queued) = self.health.counts();
        if checking + queued > 0 {
            status.push_str(&format!(" · Health {checking} checking / {queued} queued"));
        }
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    status,
                    Style::default().fg(if self.job.is_some() { YELLOW } else { MUTED }),
                ),
                Line::from(vec![
                    Span::styled(" ? ", Style::default().fg(CYAN).bold()),
                    Span::raw("help   "),
                    Span::styled("w", Style::default().fg(CYAN)),
                    Span::raw(" save   "),
                    Span::styled("a", Style::default().fg(CYAN)),
                    Span::raw(" apply   "),
                    Span::styled("v", Style::default().fg(CYAN)),
                    Span::raw(" validate   "),
                    Span::styled("q", Style::default().fg(CYAN)),
                    Span::raw(" quit"),
                ]),
            ])
            .block(
                Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(LINE)),
            ),
            outer[2],
        );
        if let Some(modal) = &self.modal {
            draw_modal(frame, modal);
        }
    }

    fn draw_nav(&self, frame: &mut Frame, area: Rect) {
        let parts = Layout::vertical([Constraint::Min(14), Constraint::Length(8)]).split(area);
        let counts = [
            String::new(),
            self.doc
                .entries("outbounds")
                .map(|v| v.len().to_string())
                .unwrap_or_default(),
            self.doc
                .entries("rules")
                .map(|v| v.len().to_string())
                .unwrap_or_default(),
            self.doc
                .entries("inbounds")
                .map(|v| v.len().to_string())
                .unwrap_or_default(),
            self.doc.meta.subscriptions.len().to_string(),
            String::new(),
            String::new(),
        ];
        let items: Vec<_> = TABS
            .iter()
            .enumerate()
            .map(|(i, name)| ListItem::new(format!(" {}  {:<14}{}", i + 1, name, counts[i])))
            .collect();
        let mut state = ListState::default().with_selected(Some(self.tab));
        frame.render_stateful_widget(
            List::new(items)
                .style(Style::default().fg(MUTED))
                .highlight_style(Style::default().bg(LINE).fg(CYAN).bold())
                .block(panel(" WORKSPACE ")),
            parts[0],
            &mut state,
        );
        let text = vec![
            Line::styled(" SERVICE", Style::default().fg(CYAN)),
            Line::raw(""),
            Line::raw(" s  Start"),
            Line::raw(" x  Stop"),
            Line::raw(" r  Restart"),
            Line::raw(" u  Update core"),
            Line::styled(" Tab  Next section", Style::default().fg(MUTED)),
        ];
        frame.render_widget(Paragraph::new(text).block(panel("")), parts[1]);
    }

    fn draw_overview(&self, frame: &mut Frame, area: Rect) {
        let rows = Layout::vertical([
            Constraint::Length(6),
            Constraint::Min(8),
            Constraint::Length(7),
        ])
        .spacing(1)
        .split(area);
        let cards = Layout::horizontal([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .spacing(1)
        .split(rows[0]);
        let outbound = self.doc.entries("outbounds").unwrap_or_default();
        let rules = self.doc.entries("rules").unwrap_or_default();
        let default = outbound
            .iter()
            .find(|e| e.active_index == Some(0))
            .map(|e| strv(&e.value, "tag"))
            .unwrap_or("—");
        for (i, title, large, small) in [
            (
                0,
                " CORE ",
                self.status.active.to_uppercase(),
                format!("PID {} · {}", self.status.pid, self.status.memory),
            ),
            (
                1,
                " CONNECTIONS ",
                format!(
                    "{} active",
                    outbound.iter().filter(|e| e.active_index.is_some()).count()
                ),
                format!(
                    "{} paused",
                    outbound
                        .iter()
                        .filter(|e| e.disabled_index.is_some())
                        .count()
                ),
            ),
            (
                2,
                " ROUTING ",
                format!(
                    "{} rules",
                    rules.iter().filter(|e| e.active_index.is_some()).count()
                ),
                format!("{} subscriptions", self.doc.meta.subscriptions.len()),
            ),
        ] {
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled(
                        large,
                        Style::default()
                            .fg(if i == 0 { GREEN } else { CYAN })
                            .bold(),
                    ),
                    Line::raw(""),
                    Line::styled(small, Style::default().fg(MUTED)),
                ])
                .block(panel(title)),
                cards[i],
            );
        }
        let lines = vec![
            Line::styled(
                "Your network, in one place",
                Style::default().fg(TEXT).bold(),
            ),
            Line::raw(""),
            kv("Default outbound", default),
            kv(
                "Service",
                &format!(
                    "{} ({})",
                    self.service.unit,
                    if self.service.user { "user" } else { "system" }
                ),
            ),
            kv("Version", &self.status.version),
            Line::raw(""),
            Line::styled("Config", Style::default().fg(MUTED)),
            Line::raw(self.doc.path.display().to_string()),
            Line::raw(""),
            Line::styled("Binary", Style::default().fg(MUTED)),
            Line::raw(self.service.binary.display().to_string()),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel(" AT A GLANCE "))
                .wrap(Wrap { trim: false }),
            rows[1],
        );
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "1  Edit a connection or route. Space pauses it in the draft.",
                    Style::default().fg(TEXT),
                ),
                Line::raw("2  Press v to test with your installed Xray."),
                Line::raw("3  Press w to save, or a to save and restart with rollback."),
                Line::raw(""),
                Line::styled(
                    "Comments are preserved. A private backup is created on every save.",
                    Style::default().fg(MUTED),
                ),
            ])
            .block(panel(" SAFE WORKFLOW ")),
            rows[2],
        );
    }

    fn draw_entries(&mut self, frame: &mut Frame, area: Rect) {
        let vertical = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(area);
        let hint = match self.tab {
            1 => {
                "t test · T all · Ctrl-T extended · p auto · h report · H settings\nn new / i import · e JSON · Space pause · d default · J/K reorder"
            }
            2 => "n new route   Enter form   e JSON   Space pause   J/K priority",
            _ => "n new listener   e JSON   Space pause   J/K reorder",
        };
        frame.render_widget(
            Paragraph::new(hint).style(Style::default().fg(MUTED)),
            vertical[0],
        );
        let columns = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
            .spacing(1)
            .split(vertical[1]);
        let entries = self.entries();
        self.selected[self.tab] = self.selected[self.tab].min(entries.len().saturating_sub(1));
        let selected = self.selected[self.tab];
        let items: Vec<_> = entries
            .iter()
            .map(|e| {
                let active = e.active_index.is_some();
                let state = if active { "●" } else { "○" };
                let title = entry_title(e, self.tab);
                let detail = if self.tab == 2 {
                    route_match(&e.value)
                } else {
                    endpoint(&e.value)
                };
                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(
                            format!(" {state} "),
                            Style::default().fg(if active { GREEN } else { MUTED }),
                        ),
                        Span::styled(
                            title,
                            Style::default().fg(if active { TEXT } else { MUTED }),
                        ),
                    ]),
                    Line::styled(format!("   {detail}"), Style::default().fg(MUTED)),
                    if self.tab == 1 {
                        let result = self.health.summary(
                            &self.doc,
                            e,
                            &self.health_settings(),
                            &self.service,
                        );
                        let color = health_color(result.state);
                        Line::styled(format!("   {}", result.text), Style::default().fg(color))
                    } else {
                        Line::raw("")
                    },
                ])
            })
            .collect();
        let mut state = ListState::default().with_selected(if entries.is_empty() {
            None
        } else {
            Some(selected)
        });
        let title = format!(
            " {} · {}{} ",
            TABS[self.tab],
            entries.len(),
            if self.filter.is_empty() {
                String::new()
            } else {
                format!(" · /{}", self.filter)
            }
        );
        frame.render_stateful_widget(
            List::new(items)
                .highlight_style(Style::default().bg(LINE))
                .block(panel(&title)),
            columns[0],
            &mut state,
        );
        if entries.is_empty() {
            frame.render_widget(
                Paragraph::new("No entries yet.\nPress n to add one, or i to import.")
                    .style(Style::default().fg(MUTED))
                    .block(panel(" DETAILS ")),
                columns[1],
            );
        } else {
            let e = &entries[selected];
            let value = config::redacted(e.value.clone());
            let mut raw = serde_json::to_string_pretty(&value).unwrap_or_default();
            if self.tab == 1 {
                let settings = self.health_settings();
                let summary = self.health.summary(&self.doc, e, &settings, &self.service);
                raw = format!(
                    "{} · {}\nAuto {} · ~{}s · h full report\n\n{}",
                    summary.text,
                    health::origin(&self.doc, e).label(),
                    if settings.enabled { "ON" } else { "PAUSED" },
                    settings.interval_seconds,
                    raw
                );
            }
            frame.render_widget(
                Paragraph::new(json_text(&raw))
                    .scroll((self.scroll, 0))
                    .block(panel(if e.active_index.is_some() {
                        " DETAILS · credentials hidden "
                    } else {
                        " PAUSED · stored in config comments "
                    }))
                    .wrap(Wrap { trim: false }),
                columns[1],
            );
        }
        frame.render_widget(
            Paragraph::new(if self.tab == 2 {
                "First matching rule wins · domains/IPs use Xray syntax · / filter · Del remove"
            } else {
                "The first outbound is the default · / filter · Del remove · PgUp/PgDn details"
            })
            .style(Style::default().fg(MUTED)),
            vertical[2],
        );
    }

    fn draw_subscriptions(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(6),
        ])
        .split(area);
        frame.render_widget(Paragraph::new("n add   Enter edit   u fetch selected   U fetch all   Del forget\nFetched nodes are previewed before being accepted into the draft.").style(Style::default().fg(MUTED)),chunks[0]);
        let items: Vec<_> = self
            .doc
            .meta
            .subscriptions
            .iter()
            .map(|s| {
                let host = url::Url::parse(&s.url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .unwrap_or_else(|| "invalid URL".into());
                ListItem::new(vec![
                    Line::styled(format!(" {}", s.name), Style::default().fg(CYAN).bold()),
                    Line::styled(
                        format!(
                            " {} · {} nodes · {}",
                            host,
                            s.tags.len(),
                            if s.updated.is_some() {
                                "imported"
                            } else {
                                "not fetched"
                            }
                        ),
                        Style::default().fg(MUTED),
                    ),
                    Line::raw(""),
                ])
            })
            .collect();
        let mut state = ListState::default().with_selected(if items.is_empty() {
            None
        } else {
            Some(self.selected[4].min(items.len() - 1))
        });
        frame.render_stateful_widget(
            List::new(items)
                .highlight_style(Style::default().bg(LINE))
                .block(panel(" SOURCES · private URL paths hidden ")),
            chunks[1],
            &mut state,
        );
        frame.render_widget(Paragraph::new("Supports JSON/JSONC outbounds, plain share-link lists and base64 lists.\nVLESS · VMess · Trojan · Shadowsocks · SOCKS · HTTP\nRefresh keeps paused nodes paused and retains nodes used by active routes.\nUnsupported nodes fail the import with no partial changes.").style(Style::default().fg(MUTED)).block(panel(" IMPORT POLICY ")).wrap(Wrap{trim:false}),chunks[2]);
    }

    fn draw_config(&mut self, frame: &mut Frame, area: Rect) {
        let parts = Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).split(area);
        frame.render_widget(
            Paragraph::new("Enter / e edit section   E edit entire JSONC   R reload from disk")
                .style(Style::default().fg(MUTED)),
            parts[0],
        );
        let columns = Layout::horizontal([Constraint::Length(24), Constraint::Min(1)])
            .spacing(1)
            .split(parts[1]);
        let keys = self.keys();
        self.selected[5] = self.selected[5].min(keys.len().saturating_sub(1));
        let mut state = ListState::default().with_selected(Some(self.selected[5]));
        frame.render_stateful_widget(
            List::new(keys.iter().map(|s| format!(" {s}")).collect::<Vec<_>>())
                .highlight_style(Style::default().bg(LINE).fg(CYAN))
                .block(panel(" SECTIONS ")),
            columns[0],
            &mut state,
        );
        let value = self.doc.value().unwrap_or(Value::Null);
        let raw = keys
            .get(self.selected[5])
            .map(|k| {
                serde_json::to_string_pretty(&config::redacted(value[k].clone()))
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        frame.render_widget(
            Paragraph::new(json_text(&raw))
                .scroll((self.scroll, 0))
                .block(panel(" JSONC · PgUp/PgDn scroll "))
                .wrap(Wrap { trim: false }),
            columns[1],
        );
    }
}

fn strv<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("—")
}
fn entry_title(e: &Entry, tab: usize) -> String {
    if tab == 2 {
        format!(
            "{} → {}",
            e.value["ruleTag"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("Rule {}", e.active_index.map(|i| i + 1).unwrap_or(0))),
            e.value["outboundTag"]
                .as_str()
                .or_else(|| e.value["balancerTag"].as_str())
                .unwrap_or("?")
        )
    } else {
        format!(
            "{}{}",
            strv(&e.value, "tag"),
            if tab == 1 && e.active_index == Some(0) {
                "  ★"
            } else {
                ""
            }
        )
    }
}
fn endpoint(v: &Value) -> String {
    let protocol = strv(v, "protocol");
    if let Some(s) = v
        .pointer("/settings/vnext/0")
        .or_else(|| v.pointer("/settings/servers/0"))
    {
        format!("{protocol} · {}:{}", strv(s, "address"), s["port"])
    } else if let Some(port) = v.get("port") {
        format!(
            "{protocol} · {}:{port}",
            v["listen"].as_str().unwrap_or("*")
        )
    } else {
        format!(
            "{protocol} · {}",
            v.pointer("/streamSettings/network")
                .and_then(Value::as_str)
                .unwrap_or("local")
        )
    }
}
fn route_match(v: &Value) -> String {
    let mut parts = Vec::new();
    for key in ["domain", "ip", "port", "network", "inboundTag", "protocol"] {
        if let Some(value) = v.get(key) {
            let text = if let Some(a) = value.as_array() {
                a.iter()
                    .take(2)
                    .map(|v| v.as_str().unwrap_or("?"))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string())
            };
            parts.push(format!("{key}: {text}"));
        }
    }
    parts.join(" · ")
}
fn panel(title: &str) -> Block<'_> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(LINE))
        .style(Style::default().bg(PANEL).fg(TEXT))
}

fn health_color(state: HealthState) -> Color {
    match state {
        HealthState::Ok => GREEN,
        HealthState::Failed => RED,
        HealthState::Partial => YELLOW,
        HealthState::Checking | HealthState::Queued => CYAN,
        _ => MUTED,
    }
}
fn kv(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key:<19}"), Style::default().fg(MUTED)),
        Span::raw(value.to_owned()),
    ])
}
fn json_text(text: &str) -> Text<'static> {
    Text::from(
        text.lines()
            .map(|line| {
                if let Some((key, value)) = line.split_once(':') {
                    Line::from(vec![
                        Span::styled(format!("{key}:"), Style::default().fg(CYAN)),
                        Span::styled(value.to_owned(), Style::default().fg(TEXT)),
                    ])
                } else {
                    Line::styled(line.to_owned(), Style::default().fg(MUTED))
                }
            })
            .collect::<Vec<_>>(),
    )
}
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width.saturating_sub(4));
    let h = height.min(area.height.saturating_sub(2));
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

fn draw_modal(frame: &mut Frame, modal: &Modal) {
    let (width, height) = match modal {
        Modal::Report { .. } => (108, 36),
        Modal::Edit(_) => (112, 36),
        Modal::Form(f) => (102, (f.fields.len() * 3 + 6) as u16),
        Modal::Help => (100, 36),
        Modal::Confirm { body, .. } => (94, (body.lines().count() + 7).clamp(12, 32) as u16),
        Modal::Message(_, s) => (102, (s.lines().count() + 5).clamp(12, 32) as u16),
    };
    let area = centered(frame.area(), width, height);
    frame.render_widget(Clear, area);
    match modal {
        Modal::Report {
            title,
            body,
            scroll,
        } => {
            frame.render_widget(panel(&format!(" {title} ")), area);
            let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(1)])
                .split(area.inner(ratatui::layout::Margin::new(1, 1)));
            frame.render_widget(
                Paragraph::new(body.as_str())
                    .scroll((*scroll, 0))
                    .wrap(Wrap { trim: false }),
                rows[0],
            );
            frame.render_widget(
                Paragraph::new("↑/↓ / PgUp/PgDn scroll · Enter/Esc close")
                    .style(Style::default().fg(CYAN)),
                rows[1],
            );
        }
        Modal::Confirm { title, body, .. } => {
            frame.render_widget(
                Paragraph::new(format!("{body}\n\n[y] Confirm     [n / Esc] Cancel"))
                    .block(panel(&format!(" {title} ")))
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
        Modal::Message(title, text) => {
            frame.render_widget(
                Paragraph::new(format!("{text}\n\nEnter / Esc to close"))
                    .block(panel(&format!(" {title} ")))
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
        Modal::Help => {
            let help = "NAVIGATION\n  1–7 / Tab / Shift-Tab       Switch section\n  j/k / ↑↓                    Select item or scroll logs\n  PgUp / PgDn                 Scroll details\n  /                           Filter connections / routes\n\nCONNECTIONS & ROUTES\n  n                           Add a connection, listener or route\n  i                           Import JSONC / share links / base64\n  t / T / Ctrl-T              Test selected / all / extended\n  p / h / H                   Auto pause / health report / settings\n  Enter                       Edit route form / item JSON\n  e                           Edit item JSONC\n  Space                       Pause / enable in draft\n  J / K                       Move down / up (rule priority)\n  d                           Use selected outbound as default\n  Del                         Delete item / forget subscription\n\nCONFIG & SERVICE\n  E                           Edit complete config.jsonc\n  v / w / a                   Validate / save / save and restart\n  R                           Reload file, discard draft\n  s / x / r                   Start / stop / restart saved config\n  u                           Official Xray update (with preview)\n  u / U in Subscriptions      Fetch selected / all sources\n  l / r in Logs               Refresh systemd journal\n  q                           Quit (checks unsaved changes)\n\nEDITORS    Ctrl-S accept draft · Esc cancel · paste supported\nFORMS      Tab/↑↓ next field · Ctrl-U clear field · Ctrl-S accept";
            frame.render_widget(
                Paragraph::new(help)
                    .block(panel(" KEYBOARD · Esc closes "))
                    .style(Style::default().fg(TEXT)),
                area,
            );
        }
        Modal::Edit(e) => {
            let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(3)])
                .split(area.inner(ratatui::layout::Margin::new(1, 1)));
            frame.render_widget(panel(&format!(" {} ", e.title)), area);
            let (row, col) = cursor_position(&e.text, e.cursor);
            let scroll = row.saturating_sub(rows[0].height.saturating_sub(2) as usize);
            let horizontal = col.saturating_sub(rows[0].width.saturating_sub(2) as usize);
            frame.render_widget(
                Paragraph::new(e.text.clone())
                    .scroll((scroll as u16, horizontal as u16))
                    .style(Style::default().fg(TEXT)),
                rows[0],
            );
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled(
                        "Ctrl-S accept draft · Esc cancel · Ctrl-U clear · paste JSON / links",
                        Style::default().fg(CYAN),
                    ),
                    Line::styled(e.error.clone(), Style::default().fg(RED)),
                ])
                .wrap(Wrap { trim: false }),
                rows[1],
            );
            frame.set_cursor_position((
                rows[0].x + (col - horizontal) as u16,
                rows[0].y + (row - scroll) as u16,
            ));
        }
        Modal::Form(f) => {
            frame.render_widget(panel(&format!(" {} ", f.title)), area);
            let inner = area.inner(ratatui::layout::Margin::new(2, 1));
            let available = inner.height.saturating_sub(3) / 3;
            let start = f.field.saturating_sub(available.saturating_sub(1) as usize);
            for (offset, (label, value)) in f
                .fields
                .iter()
                .skip(start)
                .take(available as usize)
                .enumerate()
            {
                let i = start + offset;
                let y = inner.y + (offset * 3) as u16;
                frame.render_widget(
                    Paragraph::new(label.as_str()).style(Style::default().fg(if i == f.field {
                        CYAN
                    } else {
                        MUTED
                    })),
                    Rect::new(inner.x, y, inner.width, 1),
                );
                let text = if i == f.field {
                    let mut text = value.clone();
                    text.insert(f.cursor, '▏');
                    text
                } else {
                    value.clone()
                };
                let len = text.chars().count();
                let tail: String = text
                    .chars()
                    .skip(len.saturating_sub(inner.width as usize))
                    .collect();
                frame.render_widget(
                    Paragraph::new(tail).style(
                        Style::default()
                            .bg(if i == f.field { LINE } else { PANEL })
                            .fg(TEXT),
                    ),
                    Rect::new(inner.x, y + 1, inner.width, 1),
                );
            }
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled(
                        "Tab / ↑↓ field · Ctrl-U clear · Ctrl-S accept draft · Esc cancel",
                        Style::default().fg(CYAN),
                    ),
                    Line::styled(f.error.clone(), Style::default().fg(RED)),
                ])
                .wrap(Wrap { trim: false }),
                Rect::new(inner.x, inner.bottom().saturating_sub(3), inner.width, 3),
            );
        }
    }
}

fn cursor_position(text: &str, cursor: usize) -> (usize, usize) {
    let before = &text[..cursor];
    (
        before.matches('\n').count(),
        before.rsplit('\n').next().unwrap_or("").chars().count(),
    )
}
fn edit_key(e: &mut Editor, key: KeyEvent) {
    let prev = |s: &str, i: usize| s[..i].char_indices().last().map(|(i, _)| i).unwrap_or(0);
    let next = |s: &str, i: usize| s[i..].chars().next().map(|c| i + c.len_utf8()).unwrap_or(i);
    match key.code {
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            e.text.clear();
            e.cursor = 0;
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            e.text.insert(e.cursor, c);
            e.cursor += c.len_utf8();
        }
        KeyCode::Enter => {
            e.text.insert(e.cursor, '\n');
            e.cursor += 1;
        }
        KeyCode::Backspace if e.cursor > 0 => {
            let p = prev(&e.text, e.cursor);
            e.text.drain(p..e.cursor);
            e.cursor = p;
        }
        KeyCode::Delete if e.cursor < e.text.len() => {
            let n = next(&e.text, e.cursor);
            e.text.drain(e.cursor..n);
        }
        KeyCode::Left => e.cursor = prev(&e.text, e.cursor),
        KeyCode::Right => e.cursor = next(&e.text, e.cursor),
        KeyCode::Home => e.cursor = e.text[..e.cursor].rfind('\n').map(|p| p + 1).unwrap_or(0),
        KeyCode::End => {
            e.cursor = e.text[e.cursor..]
                .find('\n')
                .map(|p| e.cursor + p)
                .unwrap_or(e.text.len())
        }
        KeyCode::Up | KeyCode::Down => {
            let (row, col) = cursor_position(&e.text, e.cursor);
            let target = if key.code == KeyCode::Up {
                row.saturating_sub(1)
            } else {
                (row + 1).min(e.text.matches('\n').count())
            };
            let mut offset = 0;
            for (i, line) in e.text.split('\n').enumerate() {
                if i == target {
                    e.cursor = offset
                        + line
                            .char_indices()
                            .nth(col)
                            .map(|(i, _)| i)
                            .unwrap_or(line.len());
                    break;
                }
                offset += line.len() + 1;
            }
        }
        _ => (),
    }
}

pub fn demo_document(path: std::path::PathBuf) -> Result<Document> {
    Document::from_text(path, include_str!("../examples/demo.jsonc").into())
}

pub fn snapshot(app: &mut App, path: &std::path::Path) -> Result<()> {
    use ratatui::{Terminal, backend::TestBackend};
    let mut terminal = Terminal::new(TestBackend::new(132, 42))?;
    terminal.draw(|f| app.draw(f))?;
    let buffer = terminal.backend().buffer();
    let mut svg = String::from(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1320\" height=\"840\" viewBox=\"0 0 1320 840\"><rect width=\"100%\" height=\"100%\" fill=\"#111620\"/><g font-family=\"DejaVu Sans Mono,monospace\" font-size=\"16\">",
    );
    let color = |c: Color| match c {
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        _ => "#d4deed".into(),
    };
    for y in 0..42 {
        for x in 0..132 {
            let cell = &buffer[(x, y)];
            if cell.bg != Color::Reset && cell.bg != BG {
                svg.push_str(&format!(
                    "<rect x=\"{}\" y=\"{}\" width=\"10\" height=\"20\" fill=\"{}\"/>",
                    x * 10,
                    y * 20,
                    color(cell.bg)
                ));
            }
            let s = cell.symbol();
            if s == " " {
                continue;
            }
            let s = s
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;");
            svg.push_str(&format!(
                "<text x=\"{}\" y=\"{}\" fill=\"{}\"{}>{s}</text>",
                x * 10,
                y * 20 + 16,
                color(cell.fg),
                if cell.modifier.contains(Modifier::BOLD) {
                    " font-weight=\"bold\""
                } else {
                    ""
                }
            ));
        }
    }
    svg.push_str("</g></svg>");
    std::fs::write(path, svg)?;
    Ok(())
}

#[cfg(test)]
mod idle_tests {
    use super::*;
    use crate::service::Options;
    use clap::Parser;

    fn app() -> App {
        let service = Service::discover(&Options::parse_from(["xray-tui", "--demo"])).unwrap();
        App::new(demo_document(service.config.clone()).unwrap(), service)
    }

    #[test]
    fn unchanged_idle_polls_do_not_request_frames_even_when_auto_is_paused() {
        let mut app = app();
        app.key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert!(!app.health_settings().enabled);
        app.poll(); // Initialize dependency stamps.
        assert_eq!(app.poll_interval(), Duration::from_millis(250));
        for _ in 0..100 {
            assert!(!app.poll());
        }
        // Time alone is not a reason to redraw an empty health view.
        app.last_health_display = Instant::now() - Duration::from_secs(2);
        assert!(!app.poll());
    }

    #[test]
    fn background_completion_and_service_changes_request_frames_without_input() {
        let mut app = app();
        app.poll();
        let (tx, rx) = mpsc::channel();
        app.job = Some(rx);
        assert_eq!(app.poll_interval(), Duration::from_millis(80));
        tx.send(Job::Message("finished".into())).unwrap();
        assert!(app.poll());
        assert_eq!(app.message, "finished");

        // A status refresh with identical data should not redraw the screen.
        app.last_status = Instant::now();
        let (tx, rx) = mpsc::channel();
        app.status_job = Some(rx);
        tx.send(Ok(app.status.clone())).unwrap();
        assert!(!app.poll());
        let (tx, rx) = mpsc::channel();
        app.status_job = Some(rx);
        let mut status = app.status.clone();
        status.active = "inactive".into();
        tx.send(Ok(status)).unwrap();
        assert!(app.poll());
        assert_eq!(app.status.active, "inactive");
    }
}
