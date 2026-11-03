use super::*;
use crate::{app::demo_document, service::Options};
use clap::Parser;
use serde_json::json;

fn fixture() -> (Document, Service, Entry) {
    let doc = demo_document("/demo/config.jsonc".into()).unwrap();
    let service = Service::discover(&Options::parse_from(["xray-tui", "--demo"])).unwrap();
    let entry = doc.entries("outbounds").unwrap().remove(0);
    (doc, service, entry)
}
fn sample(at: u64, ok: usize) -> Sample {
    Sample {
        at,
        origin: Origin::Saved,
        extended: false,
        targets: (0..2)
            .map(|i| TargetResult {
                name: format!("target-{i}"),
                stage: if i < ok { Stage::Ok } else { Stage::Timeout },
                elapsed_ms: 150 + i as u64,
                bytes: 0,
                status: None,
                detail: "test".into(),
            })
            .collect(),
    }
}
#[test]
fn isolated_profile_forces_target_keeps_dns_and_chains_without_live_listeners() {
    let (mut doc, _, entry) = fixture();
    doc.set_section("dns",r#"{"tag":"dns-tunnel","servers":["https://1.1.1.1/dns-query"],"hosts":{"edge.example.com":"192.0.2.1"}}"#).unwrap();
    doc.set_section(
        "api",
        r#"{"tag":"api","listen":"127.0.0.1:10085","services":["StatsService"]}"#,
    )
    .unwrap();
    doc.set_section("observatory", r#"{"subjectSelector":["backup"]}"#)
        .unwrap();
    let original = doc.rendered().unwrap();
    let profile = probe::profile(&doc, &entry, 32100, "random-user", "random-password").unwrap();
    assert_eq!(profile["dns"], doc.value().unwrap()["dns"]);
    assert_eq!(profile["outbounds"][0]["tag"], "aurora");
    assert_eq!(profile["inbounds"].as_array().unwrap().len(), 1);
    assert_eq!(profile["inbounds"][0]["settings"]["auth"], "password");
    assert_eq!(profile["routing"]["rules"][0]["outboundTag"], "aurora");
    assert_eq!(
        profile["routing"]["rules"][0]["inboundTag"][0],
        profile["inbounds"][0]["tag"]
    );
    for key in ["api", "observatory", "metrics", "reverse"] {
        assert!(profile.get(key).is_none());
    }
    assert!(profile["log"].get("access").is_none());
    assert_eq!(doc.rendered().unwrap(), original);
}
#[test]
fn disabled_nodes_can_be_probed_and_missing_or_cyclic_chains_fail() {
    let (mut doc, _, _) = fixture();
    let entry = doc.entries("outbounds").unwrap().remove(3);
    doc.toggle("outbounds", &entry).unwrap();
    let entry = doc
        .entries("outbounds")
        .unwrap()
        .into_iter()
        .find(|e| e.disabled_index.is_some())
        .unwrap();
    let profile = probe::profile(&doc, &entry, 1, "u", "p").unwrap();
    assert!(
        profile["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["tag"] == "backup")
    );
    assert_eq!(origin(&doc, &entry), Origin::Draft);
    let mut entry = entry.clone();
    entry.value["proxySettings"] = json!({"tag":"missing"});
    assert!(
        probe::profile(&doc, &entry, 1, "u", "p")
            .unwrap_err()
            .to_string()
            .contains("dependency")
    );
    entry.value["proxySettings"] = json!({"tag":"backup"});
    assert!(
        probe::profile(&doc, &entry, 1, "u", "p")
            .unwrap_err()
            .to_string()
            .contains("cycle")
    );
}
#[test]
fn statuses_use_hysteresis_recovery_and_expiry() {
    let settings = Settings::default();
    let mut r = Record {
        tag: "one".into(),
        key: "key".into(),
        samples: VecDeque::new(),
    };
    assert_eq!(summarize(Some(&r), &settings, 100).state, State::Unknown);
    r.samples.push_back(sample(100, 2));
    assert_eq!(summarize(Some(&r), &settings, 101).state, State::Ok);
    r.samples.push_back(sample(102, 1));
    assert_eq!(summarize(Some(&r), &settings, 103).state, State::Partial);
    for time in 104..107 {
        r.samples.push_back(sample(time, 0));
    }
    assert_eq!(summarize(Some(&r), &settings, 107).state, State::Failed);
    r.samples.push_back(sample(108, 2));
    assert_eq!(
        summarize(Some(&r), &settings, 108).text,
        "~ Recovering · 1/2 · 0s ago"
    );
    r.samples.push_back(sample(109, 2));
    assert_eq!(summarize(Some(&r), &settings, 110).state, State::Ok);
    assert_eq!(summarize(Some(&r), &settings, 230).state, State::Stale);
}
#[test]
fn fingerprints_invalidate_network_changes_but_not_auto_toggle() {
    let (mut doc, service, entry) = fixture();
    let mut settings = Settings::default();
    let key = fingerprint(&doc, &entry, &settings, &service);
    settings.enabled = false;
    settings.interval_seconds = 120;
    assert_eq!(key, fingerprint(&doc, &entry, &settings, &service));
    settings.targets[0].url = "https://example.com/204".into();
    assert_ne!(key, fingerprint(&doc, &entry, &settings, &service));
    let settings = Settings::default();
    doc.set_section("dns", r#"{"servers":["localhost"]}"#)
        .unwrap();
    assert_ne!(key, fingerprint(&doc, &entry, &settings, &service));
}

#[test]
fn cached_results_follow_edits_settings_and_save_without_losing_pause_history() {
    let (mut doc, service, entry) = fixture();
    let mut monitor = Monitor::new(&service);
    let mut settings = Settings::default();
    let key = fingerprint(&doc, &entry, &settings, &service);
    monitor.records.insert(
        key.clone(),
        Record {
            tag: "aurora".into(),
            key,
            samples: VecDeque::from([sample(now(), 2)]),
        },
    );
    assert_eq!(
        monitor.summary(&doc, &entry, &settings, &service).state,
        State::Ok
    );
    settings.enabled = false;
    assert_eq!(
        monitor.summary(&doc, &entry, &settings, &service).state,
        State::Ok
    );
    settings.timeout_seconds += 1;
    assert_eq!(
        monitor.summary(&doc, &entry, &settings, &service).state,
        State::Unknown
    );
    settings.timeout_seconds -= 1;
    assert_eq!(
        monitor.summary(&doc, &entry, &settings, &service).state,
        State::Ok
    );

    doc.set_section("dns", r#"{"servers":["localhost"]}"#)
        .unwrap();
    let draft_key = fingerprint(&doc, &entry, &settings, &service);
    assert_eq!(
        monitor.summary(&doc, &entry, &settings, &service).state,
        State::Unknown
    );
    monitor.records.insert(
        draft_key.clone(),
        Record {
            tag: "aurora".into(),
            key: draft_key,
            samples: VecDeque::from([sample(now(), 2)]),
        },
    );
    assert_eq!(
        monitor.summary(&doc, &entry, &settings, &service).state,
        State::Ok
    );
    doc.original = doc.text.clone();
    assert_eq!(
        monitor.summary(&doc, &entry, &settings, &service).state,
        State::Unknown,
        "a saved configuration must not inherit a draft's results"
    );
}

#[test]
fn cached_results_expire_after_binary_or_ca_replacement_and_manual_test_reads_immediately() {
    let (doc, demo, entry) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let mut service = demo.clone();
    service.demo = false;
    service.binary = dir.path().join("xray");
    service.config = dir.path().join("config.jsonc");
    fs::write(&service.config, doc.rendered().unwrap()).unwrap();
    fs::write(&service.binary, "core-v1").unwrap();
    let settings = Settings {
        enabled: false,
        ca_certificate: Some(dir.path().join("ca.pem")),
        ..Settings::default()
    };
    fs::write(settings.ca_certificate.as_ref().unwrap(), "cert-v1").unwrap();
    let mut monitor = Monitor::new(&demo);
    let key = monitor.cached_key(&doc, &entry, &settings, &service);
    monitor.records.insert(
        key.clone(),
        Record {
            tag: "aurora".into(),
            key,
            samples: VecDeque::from([sample(now(), 2)]),
        },
    );
    assert_eq!(
        monitor.summary(&doc, &entry, &settings, &service).state,
        State::Ok
    );
    fs::write(&service.binary, "replacement-core-v2").unwrap();
    monitor.fingerprints.borrow_mut().files.as_mut().unwrap().0 =
        Instant::now() - Duration::from_secs(6);
    assert!(monitor.tick(&service, &settings, false));
    assert_eq!(
        monitor.summary(&doc, &entry, &settings, &service).state,
        State::Unknown
    );

    let before_ca = monitor.cached_key(&doc, &entry, &settings, &service);
    fs::write(settings.ca_certificate.as_ref().unwrap(), "cert-v2").unwrap();
    // No sleeps or cache expiry: an explicit test must use the new file immediately.
    monitor
        .enqueue(&doc, &entry, &settings, &service, false)
        .unwrap();
    let task = monitor.queue.front().unwrap();
    assert_ne!(task.key, before_ca);
    assert_eq!(task.key, fingerprint(&doc, &entry, &settings, &service));
}
#[test]
fn settings_roundtrip_in_config_comments_and_validate() {
    let (mut doc, _, _) = fixture();
    doc.meta.health = Some(Settings::default());
    let rendered = doc.rendered().unwrap();
    let restored = Document::from_text(doc.path.clone(), rendered).unwrap();
    assert_eq!(doc.meta.health, restored.meta.health);
    let mut settings = Settings::default();
    settings.targets[0].url = "http://example.com/".into();
    assert!(settings.validate().is_err());
    settings = Settings::default();
    settings.concurrency = 3;
    assert!(settings.validate().is_err());
    settings = Settings::default();
    settings.extended_target.max_bytes = 2 * 1024 * 1024;
    assert!(settings.validate().is_err());
}
#[test]
fn queue_deduplicates_bounds_workers_and_history_retains_twenty() {
    let (doc, demo, entry) = fixture();
    let mut service = demo.clone();
    service.demo = false;
    service.binary = "/bin/false".into();
    service.working_dir = "/tmp".into();
    let mut monitor = Monitor::new(&demo);
    let settings = Settings::default();
    assert!(
        monitor
            .enqueue(&doc, &entry, &settings, &service, false)
            .unwrap()
    );
    assert!(
        !monitor
            .enqueue(&doc, &entry, &settings, &service, true)
            .unwrap()
    );
    for e in doc
        .entries("outbounds")
        .unwrap()
        .into_iter()
        .skip(1)
        .filter(probeable)
    {
        let _ = monitor.enqueue(&doc, &e, &settings, &service, false);
    }
    monitor.pause_periodic();
    assert_eq!(
        monitor.counts().1,
        3,
        "manual tasks must survive pausing auto mode"
    );
    monitor.tick(&service, &settings, false);
    assert_eq!(monitor.counts(), (2, 1));
    let key = fingerprint(&doc, &entry, &settings, &service);
    monitor
        .records
        .entry(key.clone())
        .or_insert_with(|| Record {
            tag: "aurora".into(),
            key: key.clone(),
            samples: VecDeque::new(),
        });
    for i in 0..25 {
        monitor.record(&key, sample(100 + i, 2));
    }
    assert_eq!(monitor.records[&key].samples.len(), 20);
    assert!(
        monitor
            .report(&doc, &entry, &settings, &service)
            .contains("HISTORY")
    );
}

#[test]
fn periodic_queue_reads_disk_instead_of_unsaved_draft_and_store_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let (mut doc, demo, _) = fixture();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("config.jsonc");
    fs::write(&path, doc.rendered().unwrap()).unwrap();
    let saved = Document::load(&path).unwrap();
    doc.path = path.clone();
    doc.set_section("dns", r#"{"servers":["draft.invalid"]}"#)
        .unwrap();
    let mut service = demo.clone();
    service.demo = false;
    service.binary = "/bin/false".into();
    service.config = path;
    service.working_dir = root.path().into();
    let mut monitor = Monitor::new(&demo);
    let settings = Settings::default();
    monitor.tick(&service, &settings, true);
    assert!(
        monitor
            .queue
            .iter()
            .all(|t| t.doc.value().unwrap() == saved.value().unwrap())
    );
    for entry in saved
        .entries("outbounds")
        .unwrap()
        .into_iter()
        .filter(probeable)
        .take(2)
    {
        let key = fingerprint(&saved, &entry, &settings, &service);
        assert!(monitor.records.contains_key(&key));
        assert_ne!(key, fingerprint(&doc, &entry, &settings, &service));
    }
    let key = monitor.records.keys().next().unwrap().clone();
    monitor.pause_periodic();
    assert!(
        monitor
            .running
            .values()
            .all(|r| r.cancel.load(Ordering::Relaxed))
    );
    monitor.record(&key, sample(now(), 2));
    let store = root.path().join("state/history.json");
    monitor.store = Some(store.clone());
    drop(monitor);
    assert_eq!(
        fs::metadata(&store).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let history: History = serde_json::from_slice(&fs::read(store).unwrap()).unwrap();
    assert_eq!(history.version, 1);
    assert!(
        !serde_json::to_string(&history)
            .unwrap()
            .contains("edge.example.com")
    );
}
