use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt};
use xray_tui::{
    app::{self, App},
    config::{self, Document, Subscription},
    import,
    service::{Options, Service},
    update,
};

fn doc() -> Document {
    app::demo_document("/demo/config.jsonc".into()).unwrap()
}
fn service() -> Service {
    Service::discover(&Options::parse_from(["xray-tui", "--demo"])).unwrap()
}
fn key(app: &mut App, code: KeyCode) {
    app.key(KeyEvent::new(code, KeyModifiers::NONE));
}
fn accept(app: &mut App) {
    app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
}

#[test]
fn cached_document_reads_follow_edits_save_and_disabled_metadata() {
    let mut d = doc();
    let original = d.value().unwrap();
    let entries = d.entries("outbounds").unwrap();
    assert!(d.same_as_original());

    // Full-editor and save jobs assign these public fields directly.
    d.text = d.text.replace("aurora", "renamed");
    assert_ne!(d.value().unwrap(), original);
    assert_eq!(d.entries("outbounds").unwrap()[0].value["tag"], "renamed");
    assert!(!d.same_as_original());
    d.original = d.text.clone();
    assert!(d.same_as_original());

    let e = d.entries("outbounds").unwrap().remove(3);
    d.toggle("outbounds", &e).unwrap();
    let disabled = d
        .entries("outbounds")
        .unwrap()
        .into_iter()
        .find(|e| e.disabled_index.is_some())
        .unwrap();
    let i = disabled.disabled_index.unwrap();
    d.meta.disabled[i].raw = d.meta.disabled[i].raw.replace("backup", "disabled-new");
    let changed = d
        .entries("outbounds")
        .unwrap()
        .into_iter()
        .find(|e| e.disabled_index.is_some())
        .unwrap();
    assert_eq!(changed.value["tag"], "disabled-new");

    // An independently edited clone must not corrupt the original's cached entries.
    let mut clone = d.clone();
    clone.text = clone.text.replace("renamed", "clone");
    assert_eq!(clone.entries("outbounds").unwrap()[0].value["tag"], "clone");
    assert_eq!(d.entries("outbounds").unwrap()[0].value["tag"], "renamed");
    assert_eq!(entries[0].value["tag"], "aurora");
}

#[test]
fn jsonc_edits_preserve_other_comments_and_internal_untouched_fields() {
    let text = r#"{
      // root comment
      "outbounds": [
        // connection comment
        {"tag":"direct", /* protocol note */ "protocol":"freedom", "settings": {
          // settings note
          "domainStrategy": "AsIs"
        }}
      ],
      "routing": { /* routing note */ "rules": [] }
    }"#;
    let mut d = Document::from_text("/demo/config.jsonc".into(), text.into()).unwrap();
    let entry = d.entries("outbounds").unwrap().remove(0);
    let mut value = entry.value.clone();
    value["settings"]["domainStrategy"] = json!("UseIP");
    d.put("outbounds", Some(&entry), &value.to_string())
        .unwrap();
    for comment in [
        "root comment",
        "connection comment",
        "protocol note",
        "settings note",
        "routing note",
    ] {
        assert!(d.text.contains(comment), "lost {comment}");
    }
    assert_eq!(
        d.value().unwrap()["outbounds"][0]["settings"]["domainStrategy"],
        "UseIP"
    );
}

#[test]
fn toggle_roundtrip_retains_raw_comments_and_rule_order_after_reload() {
    let mut d = doc();
    let e = d.entries("rules").unwrap().remove(0);
    let mut raw = e.raw.clone();
    raw = raw.replacen("{", "{ /* paused rule note */", 1);
    d.put("rules", Some(&e), &raw).unwrap();
    // Object edits retain existing comments; add the note directly through the full editor.
    d.text = d.text.replacen(
        "\"type\": \"field\"",
        "/* paused rule note */ \"type\": \"field\"",
        1,
    );
    let expected = d.value().unwrap()["routing"]["rules"].clone();
    for _ in 0..2 {
        let e = d.entries("rules").unwrap().remove(0);
        d.toggle("rules", &e).unwrap();
    }
    let text = d.rendered().unwrap();
    assert!(text.starts_with("// @xray-tui:v1 "));
    let mut d = Document::from_text(d.path, text).unwrap();
    assert!(!d.dirty());
    // Restore first paused rule before the other: successor anchors keep original order.
    for _ in 0..2 {
        let e = d
            .entries("rules")
            .unwrap()
            .into_iter()
            .find(|e| e.disabled_index.is_some())
            .unwrap();
        d.toggle("rules", &e).unwrap();
    }
    assert_eq!(d.value().unwrap()["routing"]["rules"], expected);
    assert!(d.rendered().unwrap().contains("paused rule note"));
    assert!(d.meta.disabled.is_empty());
}

#[test]
fn outbound_references_and_default_are_protected() {
    let mut d = doc();
    for tag in ["aurora", "direct", "block"] {
        let e = d
            .entries("outbounds")
            .unwrap()
            .into_iter()
            .find(|e| e.value["tag"] == tag)
            .unwrap();
        assert!(d.toggle("outbounds", &e).is_err());
    }
    let e = d.entries("outbounds").unwrap().remove(3);
    d.toggle("outbounds", &e).unwrap();
    assert_eq!(d.meta.disabled.len(), 1);
    let mut d = doc();
    d.set_section(
        "dns",
        r#"{"tag":"dns","servers":[{"address":"https://example.com/dns-query","tag":"backup"}]}"#,
    )
    .unwrap();
    let e = d.entries("outbounds").unwrap().remove(3);
    assert!(d.toggle("outbounds", &e).is_err());
}

#[test]
fn priority_default_duplicate_and_missing_reference_checks() {
    let mut d = doc();
    d.move_entry("rules", 2, 0).unwrap();
    assert_eq!(
        d.value().unwrap()["routing"]["rules"][0]["ruleTag"],
        "Block ads"
    );
    d.move_entry("outbounds", 1, 0).unwrap();
    assert_eq!(d.value().unwrap()["outbounds"][0]["tag"], "direct");
    assert!(
        d.put(
            "outbounds",
            None,
            r#"{"tag":"direct","protocol":"freedom"}"#
        )
        .is_err()
    );
    d.put(
        "rules",
        None,
        r#"{"type":"field","domain":["example.org"],"outboundTag":"missing"}"#,
    )
    .unwrap();
    assert!(d.validate_structure().is_err());
}

#[test]
fn import_protocols_transports_ipv6_and_base64() {
    let id = "00000000-0000-0000-0000-000000000001";
    let link = format!(
        "vless://{id}@[2001:db8::1]:443?security=reality&pbk=example-public-key&sid=abcd&sni=example.com&type=xhttp&path=%2Ftunnel&mode=auto#Test%20Node"
    );
    let v = import::parse_uri(&link).unwrap();
    assert_eq!(v["tag"], "Test Node");
    assert_eq!(v["settings"]["vnext"][0]["address"], "2001:db8::1");
    assert_eq!(v["streamSettings"]["xhttpSettings"]["path"], "/tunnel");
    let list = STANDARD.encode(format!("{link}\ntrojan://secret@example.com:443#Backup"));
    assert_eq!(import::parse_nodes(&list).unwrap().len(), 2);
    let ss = format!(
        "ss://{}@example.com:8388#SS",
        STANDARD.encode("aes-256-gcm:secret")
    );
    assert_eq!(
        import::parse_uri(&ss).unwrap()["settings"]["servers"][0]["method"],
        "aes-256-gcm"
    );
    let vmess=STANDARD.encode(json!({"v":"2","ps":"VMess","add":"example.com","port":"443","id":id,"aid":"0","net":"ws","path":"/socket","tls":"tls"}).to_string());
    assert_eq!(
        import::parse_uri(&format!("vmess://{vmess}")).unwrap()["streamSettings"]["network"],
        "ws"
    );
    assert!(
        import::parse_nodes("vless://id@example.com:443\nhysteria2://secret@example.com:443")
            .is_err()
    );
    assert!(import::parse_uri("vless://id@example.com:443?type=kcp").is_err());
    assert!(import::parse_uri("trojan://secret@example.com:443?allowInsecure=1").is_err());
}

#[test]
fn subscription_refresh_is_transactional_preserves_paused_and_manual_nodes() {
    let d = doc();
    let sub = Subscription {
        name: "Travel".into(),
        url: "https://example.com/private-subscription".into(),
        tags: vec![],
        updated: None,
    };
    let nodes = vec![
        json!({"tag":"one","protocol":"freedom"}),
        json!({"tag":"two","protocol":"blackhole"}),
    ];
    let (mut d, _) = import::merge_subscription(&d, sub.clone(), &nodes).unwrap();
    let e = d
        .entries("outbounds")
        .unwrap()
        .into_iter()
        .find(|e| e.value["tag"] == "Travel / one")
        .unwrap();
    d.toggle("outbounds", &e).unwrap();
    d.put(
        "rules",
        None,
        r#"{"type":"field","domain":["example.net"],"outboundTag":"Travel / two"}"#,
    )
    .unwrap();
    let new = vec![json!({"tag":"one","protocol":"blackhole"})];
    let (d, message) = import::merge_subscription(&d, sub.clone(), &new).unwrap();
    assert!(message.contains("1 referenced"));
    let e = d
        .entries("outbounds")
        .unwrap()
        .into_iter()
        .find(|e| e.value["tag"] == "Travel / one")
        .unwrap();
    assert!(e.disabled_index.is_some());
    assert_eq!(e.value["protocol"], "blackhole");
    assert_eq!(d.meta.subscriptions[0].tags.len(), 2);
    assert!(
        d.entries("outbounds")
            .unwrap()
            .iter()
            .any(|e| e.value["tag"] == "aurora")
    );
    let mut conflict = doc();
    conflict
        .put(
            "outbounds",
            None,
            r#"{"tag":"Travel / one","protocol":"freedom"}"#,
        )
        .unwrap();
    let before = conflict.rendered().unwrap();
    assert!(import::merge_subscription(&conflict, sub, &nodes).is_err());
    assert_eq!(conflict.rendered().unwrap(), before);
}

#[test]
fn checksum_rejects_tampering_and_private_atomic_backups() {
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(b"archive"));
    assert!(
        update::verify_checksum(b"archive", &format!("SHA2-256(Xray-linux-64.zip)= {hash}"))
            .is_ok()
    );
    assert!(update::verify_checksum(b"tampered", &hash).is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.jsonc");
    fs::write(&path, b"original").unwrap();
    let saved = config::backup(&path).unwrap();
    config::atomic_write(&path, b"new", 0o600).unwrap();
    assert_eq!(fs::read(saved.clone()).unwrap(), b"original");
    assert_eq!(fs::read(&path).unwrap(), b"new");
    for p in [saved, path] {
        assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn tui_workflow_preview_edit_toggle_and_small_terminal() {
    let mut a = App::new(doc(), service());
    key(&mut a, KeyCode::Char('2')); // outbounds
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char('j'));
    key(&mut a, KeyCode::Char(' '));
    assert_eq!(a.doc.meta.disabled.len(), 1);
    key(&mut a, KeyCode::Char('i'));
    a.paste(r#"{"tag":"new-node","protocol":"freedom"}"#);
    accept(&mut a);
    assert!(
        !a.doc
            .entries("outbounds")
            .unwrap()
            .iter()
            .any(|e| e.value["tag"] == "new-node")
    );
    key(&mut a, KeyCode::Char('y'));
    assert!(
        a.doc
            .entries("outbounds")
            .unwrap()
            .iter()
            .any(|e| e.value["tag"] == "new-node")
    );
    for size in [(132, 42), (80, 24), (40, 10)] {
        let mut t = Terminal::new(TestBackend::new(size.0, size.1)).unwrap();
        for n in '1'..='7' {
            key(&mut a, KeyCode::Char(n));
            t.draw(|f| a.draw(f)).unwrap();
        }
    }
}

#[test]
fn route_form_accepts_unicode_and_changes_only_draft() {
    let mut a = App::new(doc(), service());
    key(&mut a, KeyCode::Char('3'));
    key(&mut a, KeyCode::Char('n'));
    a.paste("Рабочие сайты");
    key(&mut a, KeyCode::Tab);
    a.paste("aurora");
    key(&mut a, KeyCode::Tab);
    a.paste("domain:example.com, domain:example.net");
    accept(&mut a);
    let rules = a.doc.entries("rules").unwrap();
    assert_eq!(rules.last().unwrap().value["ruleTag"], "Рабочие сайты");
    assert_eq!(
        rules.last().unwrap().value["domain"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(a.doc.dirty());
}

#[test]
fn metadata_survives_urls_containing_comment_delimiters() {
    let mut d = doc();
    d.meta.subscriptions.push(Subscription {
        name: "test".into(),
        url: "https://example.com/a?token=*/secret".into(),
        tags: vec![],
        updated: None,
    });
    let text = d.rendered().unwrap();
    let reloaded = Document::from_text(d.path.clone(), text).unwrap();
    assert_eq!(
        reloaded.meta.subscriptions[0].url,
        d.meta.subscriptions[0].url
    );
    assert_eq!(reloaded.value().unwrap(), d.value().unwrap());
}

#[test]
fn raw_editors_keep_new_comments_and_api_routes_validate() {
    let mut d = doc();
    let e = d.entries("outbounds").unwrap().remove(0);
    let raw = e.raw.replacen('{', "{ /* user added comment */", 1);
    d.put_raw("outbounds", Some(&e), &raw).unwrap();
    assert!(d.text.contains("user added comment"));
    d.set_section_raw("dns", r#"{ /* DNS comment */ "servers":["localhost"] }"#)
        .unwrap();
    assert!(d.section_raw("dns").unwrap().contains("DNS comment"));
    d.set_section("api", r#"{"tag":"api","services":["StatsService"]}"#)
        .unwrap();
    d.put(
        "rules",
        None,
        r#"{"type":"field","inboundTag":["api"],"outboundTag":"api"}"#,
    )
    .unwrap();
    d.validate_structure().unwrap();
    let text = r#"{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","inboundTag":["unused-api"],"outboundTag":"api"}]}}"#;
    let d = Document::from_text("/demo/config.jsonc".into(), text.into()).unwrap();
    d.validate_structure().unwrap();
}

#[test]
fn pausing_does_not_discard_inline_annotations() {
    let text = r#"{"outbounds":[
      {"tag":"direct","protocol":"freedom"},
      /* leading */ {"tag":"backup", /* inner */ "protocol":"blackhole"} // trailing
    ]}"#;
    let mut d = Document::from_text("/demo/config.jsonc".into(), text.into()).unwrap();
    let e = d.entries("outbounds").unwrap().remove(1);
    d.toggle("outbounds", &e).unwrap();
    let rendered = d.rendered().unwrap();
    for c in ["leading", "inner", "trailing"] {
        assert!(rendered.contains(c), "lost {c} while pausing");
    }
    let mut d = Document::from_text(d.path, rendered).unwrap();
    let e = d.entries("outbounds").unwrap().remove(1);
    d.toggle("outbounds", &e).unwrap();
    for c in ["leading", "inner", "trailing"] {
        assert!(d.text.contains(c), "lost {c} while restoring");
    }
    d.validate_structure().unwrap();
}

#[test]
fn health_hotkeys_settings_and_report_do_not_block_navigation_or_edit_config() {
    let mut a = App::new(doc(), service());
    let original = a.doc.value().unwrap();
    key(&mut a, KeyCode::Char('2'));
    key(&mut a, KeyCode::Char('p'));
    assert!(!a.doc.meta.health.as_ref().unwrap().enabled);
    key(&mut a, KeyCode::Char('h'));
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| a.draw(f)).unwrap();
    key(&mut a, KeyCode::PageDown);
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('H'));
    t.draw(|f| a.draw(f)).unwrap();
    key(&mut a, KeyCode::Esc);
    key(&mut a, KeyCode::Char('3'));
    t.draw(|f| a.draw(f)).unwrap();
    assert_eq!(a.doc.value().unwrap(), original);
}
