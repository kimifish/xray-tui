//! Isolated outbound probes. No live configuration writes or systemd actions.
mod probe;
#[cfg(test)]
mod tests;

use crate::{
    config::{Document, Entry, atomic_write},
    service::Service,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    fs,
    io::Read,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Target {
    pub name: String,
    pub url: String,
    pub status: u16,
    pub contains: Option<String>,
    pub min_bytes: usize,
    pub max_bytes: usize,
}
impl Default for Target {
    fn default() -> Self {
        Self {
            name: "HTTPS".into(),
            url: String::new(),
            status: 204,
            contains: None,
            min_bytes: 0,
            max_bytes: 16384,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub ca_certificate: Option<PathBuf>,
    pub enabled: bool,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub concurrency: usize,
    pub targets: Vec<Target>,
    pub extended_target: Target,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            ca_certificate: None,
            enabled: true,
            interval_seconds: 60,
            timeout_seconds: 8,
            concurrency: 2,
            targets: vec![
                Target {
                    name: "Google 204".into(),
                    url: "https://www.gstatic.com/generate_204".into(),
                    ..Target::default()
                },
                Target {
                    name: "Cloudflare trace".into(),
                    url: "https://www.cloudflare.com/cdn-cgi/trace".into(),
                    status: 200,
                    contains: Some("ip=".into()),
                    min_bytes: 8,
                    ..Target::default()
                },
            ],
            extended_target: Target {
                name: "Cloudflare 512 KiB".into(),
                url: "https://speed.cloudflare.com/__down?bytes=524288".into(),
                status: 200,
                contains: None,
                min_bytes: 524288,
                max_bytes: 524288,
            },
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (15..=86400).contains(&self.interval_seconds),
            "interval_seconds must be 15..86400"
        );
        ensure!(
            (2..=30).contains(&self.timeout_seconds),
            "timeout_seconds must be 2..30"
        );
        ensure!(
            (1..=2).contains(&self.concurrency),
            "concurrency must be 1 or 2"
        );
        ensure!(
            (2..=8).contains(&self.targets.len()),
            "Configure 2..8 independent targets"
        );
        for t in self
            .targets
            .iter()
            .chain(std::iter::once(&self.extended_target))
        {
            let u = url::Url::parse(&t.url).context("Invalid health target URL")?;
            ensure!(
                u.scheme() == "https"
                    && u.host_str().is_some()
                    && u.username().is_empty()
                    && u.password().is_none(),
                "Health targets must be HTTPS URLs without user credentials"
            );
            ensure!(
                !t.name.is_empty() && t.name.len() <= 80,
                "Target name must contain 1..80 bytes"
            );
            ensure!(
                (100..=599).contains(&t.status),
                "Invalid expected HTTP status"
            );
            ensure!(
                t.min_bytes <= t.max_bytes && t.max_bytes <= 1024 * 1024,
                "Target body limits must satisfy min_bytes <= max_bytes <= 1 MiB"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Origin {
    Saved,
    Draft,
}
impl Origin {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Saved => "Saved",
            Self::Draft => "Draft",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Stage {
    Ok,
    Config,
    Startup,
    Dns,
    Connect,
    Tls,
    Timeout,
    Reset,
    Http,
    Body,
    Cancelled,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetResult {
    pub name: String,
    pub stage: Stage,
    pub elapsed_ms: u64,
    pub bytes: usize,
    pub status: Option<u16>,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sample {
    pub at: u64,
    pub origin: Origin,
    pub extended: bool,
    pub targets: Vec<TargetResult>,
}
impl Sample {
    pub fn successes(&self) -> usize {
        self.targets.iter().filter(|r| r.stage == Stage::Ok).count()
    }
    pub fn all_ok(&self) -> bool {
        !self.targets.is_empty() && self.successes() == self.targets.len()
    }
    pub fn delay(&self) -> Option<u64> {
        let mut a: Vec<_> = self
            .targets
            .iter()
            .filter(|r| r.stage == Stage::Ok)
            .map(|r| r.elapsed_ms)
            .collect();
        a.sort();
        a.get(a.len() / 2).copied()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub tag: String,
    pub key: String,
    pub samples: VecDeque<Sample>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Unknown,
    Checking,
    Queued,
    Ok,
    Partial,
    Failed,
    Stale,
    NotApplicable,
}
pub struct Summary {
    pub state: State,
    pub text: String,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn probeable(entry: &Entry) -> bool {
    !matches!(
        entry.value["protocol"].as_str(),
        None | Some("blackhole" | "dns" | "loopback")
    )
}
pub fn origin(doc: &Document, entry: &Entry) -> Origin {
    if entry.disabled_index.is_some() || !doc.same_as_original() {
        Origin::Draft
    } else {
        Origin::Saved
    }
}
pub fn fingerprint(
    doc: &Document,
    entry: &Entry,
    settings: &Settings,
    service: &Service,
) -> String {
    fingerprint_with_files(
        doc,
        entry,
        settings,
        &FingerprintFiles::read(settings, service),
    )
}

#[derive(PartialEq, Eq)]
struct FingerprintFiles {
    binary: PathBuf,
    stamp: Option<(u64, Option<u128>)>,
    ca_path: Option<PathBuf>,
    ca: Option<String>,
}
impl FingerprintFiles {
    fn read(settings: &Settings, service: &Service) -> Self {
        let stamp = fs::metadata(&service.binary).ok().map(|m| {
            (
                m.len(),
                m.modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|t| t.as_nanos()),
            )
        });
        let ca = settings
            .ca_certificate
            .as_ref()
            .and_then(|p| fs::read(p).ok())
            .map(|b| format!("{:x}", Sha256::digest(b)));
        Self {
            binary: service.binary.clone(),
            stamp,
            ca_path: settings.ca_certificate.clone(),
            ca,
        }
    }
}

fn fingerprint_with_files(
    doc: &Document,
    entry: &Entry,
    settings: &Settings,
    files: &FingerprintFiles,
) -> String {
    // Preserve the persisted history key format.
    let data = serde_json::json!({"config":doc.value().ok(),"outbound":entry.value,"targets":settings.targets,"extended_target":settings.extended_target,"timeout":settings.timeout_seconds,"ca":files.ca,"ca_path":files.ca_path,"binary":files.binary,"stamp":files.stamp,"origin":origin(doc,entry)});
    format!("{:x}", Sha256::digest(data.to_string()))
}

struct KeyContext {
    text: String,
    original: String,
    settings: Settings,
    entries: Vec<(serde_json::Value, bool, String)>,
}

#[derive(Default)]
struct FingerprintCache {
    files: Option<(Instant, FingerprintFiles)>,
    // The UI draft and the saved document used by the scheduler can differ.
    contexts: VecDeque<KeyContext>,
}
impl FingerprintCache {
    fn refresh_files(&mut self, settings: &Settings, service: &Service, force: bool) -> bool {
        if !force
            && self.files.as_ref().is_some_and(|(at, files)| {
                at.elapsed() < Duration::from_secs(5)
                    && files.binary == service.binary
                    && files.ca_path == settings.ca_certificate
            })
        {
            return false;
        }
        let files = FingerprintFiles::read(settings, service);
        let changed = self
            .files
            .as_ref()
            .is_none_or(|(_, previous)| previous != &files);
        if changed {
            self.contexts.clear();
        }
        self.files = Some((Instant::now(), files));
        changed
    }

    fn key(
        &mut self,
        doc: &Document,
        entry: &Entry,
        settings: &Settings,
        service: &Service,
    ) -> String {
        self.refresh_files(settings, service, false);
        let index = self
            .contexts
            .iter()
            .position(|c| {
                c.text == doc.text && c.original == doc.original && c.settings == *settings
            })
            .unwrap_or_else(|| {
                if self.contexts.len() == 2 {
                    self.contexts.pop_front();
                }
                self.contexts.push_back(KeyContext {
                    text: doc.text.clone(),
                    original: doc.original.clone(),
                    settings: settings.clone(),
                    entries: Vec::new(),
                });
                self.contexts.len() - 1
            });
        let context = &mut self.contexts[index];
        let disabled = entry.disabled_index.is_some();
        if let Some((_, _, key)) = context
            .entries
            .iter()
            .find(|(value, draft, _)| *value == entry.value && *draft == disabled)
        {
            return key.clone();
        }
        let key = fingerprint_with_files(doc, entry, settings, &self.files.as_ref().unwrap().1);
        context
            .entries
            .push((entry.value.clone(), disabled, key.clone()));
        key
    }
}

#[derive(Clone)]
struct Task {
    doc: Document,
    entry: Entry,
    settings: Settings,
    service: Service,
    key: String,
    extended: bool,
    manual: bool,
}
struct Running {
    manual: bool,
    cancel: Arc<AtomicBool>,
    handle: JoinHandle<()>,
    rx: Receiver<Sample>,
}
#[derive(Default, Serialize, Deserialize)]
struct History {
    version: u8,
    records: HashMap<String, Record>,
}

pub struct Monitor {
    fingerprints: RefCell<FingerprintCache>,
    records: HashMap<String, Record>,
    queue: VecDeque<Task>,
    running: HashMap<String, Running>,
    next_due: HashMap<String, Instant>,
    saved: Option<Document>,
    disk_check: Instant,
    schedule_check: Instant,
    store: Option<PathBuf>,
    writer: Option<JoinHandle<Result<()>>>,
    persist_dirty: bool,
    pub warning: Option<String>,
    jitter: u64,
}
impl Monitor {
    pub fn new(service: &Service) -> Self {
        let store = if service.demo {
            None
        } else {
            state_path(service)
        };
        let mut warning = None;
        let records = store
            .as_ref()
            .and_then(|p| {
                let mut bytes = Vec::new();
                fs::File::open(p)
                    .ok()?
                    .take(8 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .ok()?;
                Some(bytes)
            })
            .and_then(|b| {
                if b.len() > 8 * 1024 * 1024 {
                    warning = Some("Health history exceeds 8 MiB; ignored".into());
                    return None;
                }
                match serde_json::from_slice::<History>(&b) {
                    Ok(mut h) if h.version == 1 => {
                        for r in h.records.values_mut() {
                            while r.samples.len() > 20 {
                                r.samples.pop_front();
                            }
                        }
                        Some(h.records)
                    }
                    _ => {
                        warning = Some("Health history unreadable; starting a new history".into());
                        None
                    }
                }
            })
            .unwrap_or_default();
        Self {
            fingerprints: RefCell::new(FingerprintCache::default()),
            records,
            queue: VecDeque::new(),
            running: HashMap::new(),
            next_due: HashMap::new(),
            saved: None,
            disk_check: Instant::now() - Duration::from_secs(10),
            schedule_check: Instant::now() - Duration::from_secs(2),
            store,
            writer: None,
            persist_dirty: false,
            warning,
            jitter: now().max(1),
        }
    }

    pub fn enqueue(
        &mut self,
        doc: &Document,
        entry: &Entry,
        settings: &Settings,
        service: &Service,
        extended: bool,
    ) -> Result<bool> {
        self.enqueue_inner(doc, entry, settings, service, extended, true)
    }
    fn enqueue_inner(
        &mut self,
        doc: &Document,
        entry: &Entry,
        settings: &Settings,
        service: &Service,
        extended: bool,
        manual: bool,
    ) -> Result<bool> {
        ensure!(!service.demo, "Network checks are disabled in demo mode");
        settings.validate()?;
        ensure!(
            probeable(entry),
            "This outbound does not carry web traffic (blackhole/DNS/loopback)"
        );
        // Manual tests must see a just-replaced binary or CA immediately.
        if manual {
            self.fingerprints
                .borrow_mut()
                .refresh_files(settings, service, true);
        }
        let key = self.cached_key(doc, entry, settings, service);
        let tag = entry.value["tag"].as_str().unwrap_or("untagged");
        if self
            .running
            .keys()
            .any(|k| self.records.get(k).is_some_and(|r| r.tag == tag))
            || self.queue.iter().any(|t| t.key == key)
        {
            return Ok(false);
        }
        self.queue
            .retain(|t| t.entry.value["tag"].as_str() != Some(tag));
        ensure!(self.queue.len() < 256, "Probe queue is full");
        let task = Task {
            doc: doc.clone(),
            entry: entry.clone(),
            settings: settings.clone(),
            service: service.clone(),
            key,
            extended,
            manual,
        };
        if manual {
            self.queue.push_front(task)
        } else {
            self.queue.push_back(task)
        };
        Ok(true)
    }
    pub fn pause_periodic(&mut self) {
        self.queue.retain(|t| t.manual);
        for running in self.running.values().filter(|r| !r.manual) {
            running.cancel.store(true, Ordering::Relaxed);
        }
    }
    /// Poll background work; return whether visible health state changed.
    pub fn tick(&mut self, service: &Service, settings: &Settings, allow_schedule: bool) -> bool {
        let previous_counts = self.counts();
        let previous_warning = self.warning.clone();
        let mut changed = self
            .fingerprints
            .borrow_mut()
            .refresh_files(settings, service, false);
        let completed: Vec<_> = self
            .running
            .iter()
            .filter(|(_, r)| r.handle.is_finished())
            .map(|(k, _)| k.clone())
            .collect();
        for key in completed {
            changed = true;
            let r = self.running.remove(&key).unwrap();
            let _ = r.handle.join();
            if let Ok(sample) = r.rx.try_recv() {
                self.record(&key, sample);
            }
            let delay = self.jittered_interval(settings.interval_seconds);
            self.next_due
                .insert(key, Instant::now() + Duration::from_secs(delay));
        }
        if let Some(writer) = &self.writer
            && writer.is_finished()
            && let Err(e) = self
                .writer
                .take()
                .unwrap()
                .join()
                .unwrap_or_else(|_| Err(anyhow::anyhow!("History writer stopped")))
        {
            self.warning = Some(format!("Cannot save health history: {e}"));
        }
        if self.persist_dirty
            && self.writer.is_none()
            && let Some(path) = self.store.clone()
        {
            let bytes = self.history_bytes();
            self.writer = Some(thread::spawn(move || save_history(&path, &bytes)));
            self.persist_dirty = false;
        }
        if service.demo {
            return changed || self.warning != previous_warning;
        }
        if self.disk_check.elapsed() >= Duration::from_secs(5) {
            match Document::load(&service.config) {
                Ok(doc) => self.saved = Some(doc),
                Err(_) => {
                    self.saved = None;
                    self.warning=Some("Saved config unavailable: automatic checks are suspended; reload/fix the file".into());
                }
            }
            self.disk_check = Instant::now();
        }
        let scheduling = self.schedule_check.elapsed() >= Duration::from_secs(1);
        if scheduling {
            self.schedule_check = Instant::now();
        }
        if !allow_schedule || !settings.enabled {
            self.pause_periodic();
        } else if scheduling && let Some(saved) = &self.saved {
            let current: std::collections::HashSet<_> = saved
                .entries("outbounds")
                .unwrap_or_default()
                .iter()
                .filter(|e| e.active_index.is_some() && probeable(e))
                .map(|e| self.cached_key(saved, e, settings, service))
                .collect();
            self.queue
                .retain(|task| task.manual || current.contains(&task.key));
        }
        if scheduling
            && settings.enabled
            && allow_schedule
            && settings.validate().is_ok()
            && let Some(doc) = self.saved.clone()
        {
            for entry in doc
                .entries("outbounds")
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.active_index.is_some() && probeable(e))
            {
                let key = self.cached_key(&doc, &entry, settings, service);
                if self
                    .next_due
                    .get(&key)
                    .is_none_or(|at| *at <= Instant::now())
                    && !self.running.contains_key(&key)
                    && !self.queue.iter().any(|t| t.key == key)
                {
                    let _ = self.enqueue_inner(&doc, &entry, settings, service, false, false);
                    let jitter = self.jittered_interval(settings.interval_seconds);
                    self.next_due
                        .insert(key, Instant::now() + Duration::from_secs(jitter));
                }
            }
        }
        while self.running.len() < settings.concurrency.clamp(1, 2)
            && let Some(task) = self.queue.pop_front()
        {
            changed = true;
            let key = task.key.clone();
            let manual = task.manual;
            let cancel = Arc::new(AtomicBool::new(false));
            let flag = cancel.clone();
            let (tx, rx) = mpsc::channel();
            self.records.entry(key.clone()).or_insert_with(|| Record {
                tag: task.entry.value["tag"]
                    .as_str()
                    .unwrap_or("untagged")
                    .into(),
                key: key.clone(),
                samples: VecDeque::new(),
            });
            let handle = thread::spawn(move || {
                let result = probe::execute(
                    &task.doc,
                    &task.entry,
                    &task.settings,
                    &task.service,
                    task.extended,
                    &flag,
                );
                let _ = tx.send(result);
            });
            self.running.insert(
                key,
                Running {
                    manual,
                    cancel,
                    handle,
                    rx,
                },
            );
        }
        changed || self.counts() != previous_counts || self.warning != previous_warning
    }
    fn jittered_interval(&mut self, seconds: u64) -> u64 {
        self.jitter ^= self.jitter << 13;
        self.jitter ^= self.jitter >> 7;
        self.jitter ^= self.jitter << 17;
        let spread = (seconds / 5).max(1);
        seconds - spread + self.jitter % (spread * 2 + 1)
    }
    fn record(&mut self, key: &str, sample: Sample) {
        if sample.targets.iter().any(|r| r.stage == Stage::Cancelled) {
            return;
        }
        if let Some(record) = self.records.get_mut(key) {
            record.samples.push_back(sample);
            while record.samples.len() > 20 {
                record.samples.pop_front();
            }
        }
        if self.records.len() > 128 {
            let mut keys: Vec<_> = self
                .records
                .iter()
                .filter(|(k, _)| {
                    !self.running.contains_key(*k) && !self.queue.iter().any(|t| t.key == **k)
                })
                .map(|(k, r)| (k.clone(), r.samples.back().map(|s| s.at).unwrap_or(0)))
                .collect();
            keys.sort_by_key(|(_, at)| *at);
            for (key, _) in keys.into_iter().take(self.records.len() - 128) {
                self.records.remove(&key);
            }
        }
        self.persist_dirty = true;
    }
    pub fn summary(
        &self,
        doc: &Document,
        entry: &Entry,
        settings: &Settings,
        service: &Service,
    ) -> Summary {
        if !probeable(entry) {
            return Summary {
                state: State::NotApplicable,
                text: "N/A · non-web outbound".into(),
            };
        }
        let key = self.cached_key(doc, entry, settings, service);
        if self.running.contains_key(&key) {
            return Summary {
                state: State::Checking,
                text: format!("↻ Checking · {}", origin(doc, entry).label()),
            };
        }
        if self.queue.iter().any(|t| t.key == key) {
            return Summary {
                state: State::Queued,
                text: "… Queued".into(),
            };
        }
        summarize(self.records.get(&key), settings, now())
    }
    pub fn report(
        &self,
        doc: &Document,
        entry: &Entry,
        settings: &Settings,
        service: &Service,
    ) -> String {
        let summary = self.summary(doc, entry, settings, service);
        let key = self.cached_key(doc, entry, settings, service);
        let mut lines = vec![
            format!(
                "{} · {}",
                entry.value["tag"].as_str().unwrap_or("untagged"),
                origin(doc, entry).label()
            ),
            summary.text,
            format!(
                "Auto: {} · interval ~{}s ±20% · timeout {}s",
                if settings.enabled { "ON" } else { "PAUSED" },
                settings.interval_seconds,
                settings.timeout_seconds
            ),
            "Latency is total HTTPS request time, not ICMP ping.".into(),
            String::new(),
        ];
        if let Some(record) = self.records.get(&key)
            && let Some(last) = record.samples.back()
        {
            let successes = record.samples.iter().filter(|s| s.all_ok()).count();
            lines.push(format!(
                "Last check: {}s ago · {} · {}",
                now().saturating_sub(last.at),
                last.origin.label(),
                if last.extended { "extended" } else { "quick" }
            ));
            lines.push(format!(
                "Successful cycles: {successes}/{} (last 20)",
                record.samples.len()
            ));
            for r in &last.targets {
                lines.push(format!(
                    "{}: {:?} · {} ms · {} B · HTTP {}\n  {}",
                    r.name,
                    r.stage,
                    r.elapsed_ms,
                    r.bytes,
                    r.status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "—".into()),
                    r.detail
                ));
            }
            if let Some((sample, error)) = record.samples.iter().rev().find_map(|s| {
                s.targets
                    .iter()
                    .find(|r| r.stage != Stage::Ok)
                    .map(|r| (s, r))
            }) {
                lines.push(format!(
                    "Last failure: {}s ago · {} · {:?}\n  {}",
                    now().saturating_sub(sample.at),
                    error.name,
                    error.stage,
                    error.detail
                ));
            }
            if last.successes() == 0 {
                lines.push("Failures do not prove DPI: network, remote server or transport settings may also cause them.".into());
            }
            lines.push("\nHISTORY (newest first)".into());
            for s in record.samples.iter().rev() {
                lines.push(format!(
                    "{}s ago · {}/{} · {} ms · {}{}",
                    now().saturating_sub(s.at),
                    s.successes(),
                    s.targets.len(),
                    s.delay()
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "—".into()),
                    s.origin.label(),
                    if s.extended { " · extended" } else { "" }
                ));
            }
        } else {
            lines.push("No matching results. Press t to check this configuration.".into());
        }
        if let Some(w) = &self.warning {
            lines.push(format!("\nHistory: {w}"));
        }
        lines.join("\n")
    }
    pub fn counts(&self) -> (usize, usize) {
        (self.running.len(), self.queue.len())
    }
    pub fn has_results(&self) -> bool {
        self.records.values().any(|r| !r.samples.is_empty())
    }
    fn cached_key(
        &self,
        doc: &Document,
        entry: &Entry,
        settings: &Settings,
        service: &Service,
    ) -> String {
        self.fingerprints
            .borrow_mut()
            .key(doc, entry, settings, service)
    }
    fn history_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&History {
            version: 1,
            records: self.records.clone(),
        })
        .unwrap_or_default()
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        for r in self.running.values() {
            r.cancel.store(true, Ordering::Relaxed);
        }
        for (_, r) in self.running.drain() {
            let _ = r.handle.join();
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if self.persist_dirty
            && let Some(path) = &self.store
        {
            let _ = save_history(path, &self.history_bytes());
        }
    }
}
pub fn summarize(record: Option<&Record>, settings: &Settings, time: u64) -> Summary {
    let Some(record) = record else {
        return Summary {
            state: State::Unknown,
            text: "? Unknown".into(),
        };
    };
    let Some(last) = record.samples.back() else {
        return Summary {
            state: State::Unknown,
            text: "? Unknown".into(),
        };
    };
    if time.saturating_sub(last.at) > settings.interval_seconds * 2 {
        return Summary {
            state: State::Stale,
            text: format!("? Stale · {}s ago", time.saturating_sub(last.at)),
        };
    }
    let fails = record
        .samples
        .iter()
        .rev()
        .take_while(|s| s.successes() == 0)
        .count();
    let recovering = last.all_ok()
        && record
            .samples
            .iter()
            .rev()
            .nth(1)
            .is_some_and(|s| !s.all_ok())
        && record
            .samples
            .iter()
            .rev()
            .skip(1)
            .take(3)
            .all(|s| s.successes() == 0)
        && record.samples.len() >= 4;
    let (state, text) = if fails >= 3 {
        (State::Failed, format!("! Failed · {fails}×"))
    } else if last.all_ok() && !recovering {
        (
            State::Ok,
            format!("✓ OK · {} ms", last.delay().unwrap_or(0)),
        )
    } else if recovering {
        (State::Partial, "~ Recovering · 1/2".into())
    } else {
        (
            State::Partial,
            format!("~ Partial · {}/{}", last.successes(), last.targets.len()),
        )
    };
    Summary {
        state,
        text: format!("{text} · {}s ago", time.saturating_sub(last.at)),
    }
}
fn state_path(service: &Service) -> Option<PathBuf> {
    let root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/state")))?;
    let id = format!(
        "{:x}",
        Sha256::digest(format!(
            "{}:{}:{}",
            service.config.display(),
            service.unit,
            service.user
        ))
    );
    Some(
        root.join("xray-tui")
            .join(format!("health-{}.json", &id[..16])),
    )
}
fn save_history(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = path.parent().unwrap();
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    atomic_write(path, bytes, 0o600)
}

/// One-shot CLI path shares exactly the same engine as the scheduler.
pub fn check(
    doc: &Document,
    entry: &Entry,
    settings: &Settings,
    service: &Service,
    extended: bool,
) -> Result<Sample> {
    ensure!(!service.demo, "Network checks are disabled in demo mode");
    settings.validate()?;
    ensure!(probeable(entry), "This outbound does not carry web traffic");
    Ok(probe::execute(
        doc,
        entry,
        settings,
        service,
        extended,
        &AtomicBool::new(false),
    ))
}
