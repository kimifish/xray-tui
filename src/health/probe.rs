use super::{Sample, Settings, Stage, Target, TargetResult, now, origin};
use crate::{
    config::{Document, Entry},
    service::Service,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

pub(super) fn profile(
    doc: &Document,
    entry: &Entry,
    port: u16,
    user: &str,
    password: &str,
) -> Result<Value> {
    let original = doc.value()?;
    let tag = entry.value["tag"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("Outbound needs a tag")?;
    let mut outbounds = original["outbounds"]
        .as_array()
        .cloned()
        .context("outbounds must be an array")?;
    if let Some(i) = outbounds
        .iter()
        .position(|e| e["tag"].as_str() == Some(tag))
    {
        outbounds[i] = entry.value.clone();
    } else {
        outbounds.push(entry.value.clone());
    }
    let tags: Vec<_> = outbounds.iter().filter_map(|o| o["tag"].as_str()).collect();
    ensure!(
        tags.iter().filter(|t| **t == tag).count() == 1,
        "Ambiguous outbound tag"
    );
    for outbound in &outbounds {
        ensure!(
            !(outbound["protocol"] == "wireguard"
                && outbound.pointer("/settings/kernelMode") == Some(&Value::Bool(true))),
            "Cannot isolate a config containing WireGuard kernelMode; use userspace mode for probing"
        );
    }
    // Validate chaining for the selected outbound. Keep all configured outbounds and the
    // original default so DNS/balancer routing retains exactly its original dependencies.
    fn chain<'a>(v: &'a Value, all: &'a [Value], visiting: &mut Vec<String>) -> Result<()> {
        let tag = v["tag"].as_str().context("Chain member needs a tag")?;
        ensure!(
            !visiting.iter().any(|t| t == tag),
            "Outbound chain contains a cycle"
        );
        visiting.push(tag.into());
        let next = [
            v.pointer("/proxySettings/tag"),
            v.pointer("/streamSettings/sockopt/dialerProxy"),
        ];
        for name in next
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            let dep = all
                .iter()
                .find(|v| v["tag"].as_str() == Some(name))
                .context("Outbound chain references a disabled/missing dependency")?;
            chain(dep, all, visiting)?;
        }
        visiting.pop();
        Ok(())
    }
    chain(&entry.value, &outbounds, &mut Vec::new())?;
    ensure!(
        !matches!(
            entry.value["sendThrough"].as_str(),
            Some("origin" | "srcip")
        ),
        "sendThrough depends on the original inbound address and cannot be reproduced by a loopback probe"
    );
    let mut config = json!({"log":{"loglevel":"warning","dnsLog":false},"outbounds":outbounds});
    for key in ["dns", "routing", "transport", "policy", "fakedns"] {
        if let Some(value) = original.get(key) {
            config[key] = value.clone();
        }
    }
    let mut inbound_tag = "__xray_tui_health__".to_string();
    while original.to_string().contains(&inbound_tag) {
        inbound_tag.push('_');
    }
    config["inbounds"] = json!([{"tag":inbound_tag,"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"auth":"password","accounts":[{"user":user,"pass":password}],"udp":false}}]);
    if !config["routing"].is_object() {
        config["routing"] = json!({});
    }
    let mut rules = config["routing"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    rules.insert(
        0,
        json!({"type":"field","inboundTag":[inbound_tag],"outboundTag":tag}),
    );
    config["routing"]["rules"] = json!(rules);
    Ok(config)
}

struct Helper {
    child: Child,
    _dir: tempfile::TempDir,
    port: u16,
    user: String,
    password: String,
    log: std::path::PathBuf,
}
impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn cancelled(flag: &AtomicBool) -> Result<()> {
    ensure!(!flag.load(Ordering::Relaxed), "Probe cancelled");
    Ok(())
}
fn credentials() -> Result<(String, String)> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let hex = |b: &[u8]| b.iter().map(|n| format!("{n:02x}")).collect::<String>();
    Ok((hex(&bytes[..8]), hex(&bytes[8..])))
}
fn authenticate(port: u16, user: &str, password: &str) -> Result<()> {
    let mut s = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(100),
    )?;
    s.set_read_timeout(Some(Duration::from_millis(150)))?;
    s.set_write_timeout(Some(Duration::from_millis(150)))?;
    s.write_all(&[5, 1, 2])?;
    let mut reply = [0; 2];
    s.read_exact(&mut reply)?;
    ensure!(
        reply == [5, 2],
        "Probe listener does not require SOCKS authentication"
    );
    let mut auth = vec![1, user.len() as u8];
    auth.extend(user.as_bytes());
    auth.push(password.len() as u8);
    auth.extend(password.as_bytes());
    s.write_all(&auth)?;
    s.read_exact(&mut reply)?;
    ensure!(reply == [1, 0], "Probe listener authentication failed");
    Ok(())
}
impl Helper {
    fn start(doc: &Document, entry: &Entry, service: &Service, flag: &AtomicBool) -> Result<Self> {
        for _ in 0..3 {
            cancelled(flag)?;
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            let port = listener.local_addr()?.port();
            let (user, password) = credentials()?;
            let config = profile(doc, entry, port, &user, &password)?;
            let dir = tempfile::Builder::new()
                .prefix("xray-tui-probe-")
                .tempdir()?;
            let path = dir.path().join("config.json");
            let mut f = File::create(&path)?;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(&serde_json::to_vec(&config)?)?;
            drop(f);
            let log = dir.path().join("core.log");
            let output = File::create(&log)?;
            drop(listener); // Xray owns the listener; verify authenticated readiness and retry bind races.
            let child = Command::new(&service.binary)
                .current_dir(&service.working_dir)
                .env("XRAY_LOCATION_ASSET", service.binary.parent().unwrap())
                .args(["run", "-c"])
                .arg(&path)
                .stdin(Stdio::null())
                .stdout(output.try_clone()?)
                .stderr(output)
                .spawn()
                .context("Cannot start isolated Xray")?;
            let mut helper = Self {
                child,
                _dir: dir,
                port,
                user,
                password,
                log,
            };
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(6) {
                cancelled(flag)?;
                if helper.child.try_wait()?.is_some() {
                    let log = fs::read_to_string(&helper.log).unwrap_or_default();
                    if log.contains("address already in use") {
                        break;
                    }
                    bail!("Isolated Xray failed to start ({})", log_category(&log).1);
                }
                if authenticate(port, &helper.user, &helper.password).is_ok() {
                    return Ok(helper);
                }
                thread::sleep(Duration::from_millis(40));
            }
        }
        bail!("Isolated Xray did not open an authenticated listener")
    }
}
fn log_category(log: &str) -> (Stage, &'static str) {
    let s = log.to_lowercase();
    if s.contains("no such host") || s.contains("failed to lookup") || s.contains("dns exchange") {
        (Stage::Dns, "DNS lookup failed")
    } else if s.contains("certificate") || s.contains("tls handshake") {
        (Stage::Tls, "TLS/certificate handshake failed")
    } else if s.contains("connection refused") {
        (Stage::Connect, "Remote connection refused")
    } else if s.contains("reset by peer") {
        (Stage::Reset, "Connection reset by peer")
    } else if s.contains("timeout") || s.contains("deadline exceeded") {
        (Stage::Timeout, "Connection timed out")
    } else if s.contains("failed to load")
        || s.contains("failed to build")
        || s.contains("unknown config")
    {
        (Stage::Config, "Core rejected the isolated configuration")
    } else {
        (
            Stage::Connect,
            "Proxy connection failed; network, server or transport configuration may be responsible",
        )
    }
}
fn error_category(error: &reqwest::Error, log: &str) -> (Stage, String) {
    let mut all = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(s) = source {
        all.push_str(&format!(" {s}"));
        source = s.source();
    }
    let specific = log_category(&all);
    if specific.0 != Stage::Connect {
        return (specific.0, specific.1.into());
    }
    let from_log = log_category(log);
    if from_log.0 != Stage::Connect || from_log.1 == "Remote connection refused" {
        return (from_log.0, from_log.1.into());
    }
    if error.is_timeout() {
        return (
            Stage::Timeout,
            "HTTPS request timed out; this alone does not establish DPI".into(),
        );
    }
    (Stage::Connect, specific.1.into())
}
fn request(
    target: &Target,
    helper: &Helper,
    settings: &Settings,
    flag: &AtomicBool,
) -> TargetResult {
    let started = Instant::now();
    let mut r = TargetResult {
        name: target.name.clone(),
        stage: Stage::Ok,
        elapsed_ms: 0,
        bytes: 0,
        status: None,
        detail: "Expected HTTPS response received".into(),
    };
    if flag.load(Ordering::Relaxed) {
        r.stage = Stage::Cancelled;
        r.detail = "Cancelled".into();
        return r;
    }
    // New client/connection for every request, explicit SOCKS5h, no environment proxy and
    // no redirects. Both the remote proxy handshake and target TLS handshake are exercised.
    let work = (|| -> Result<()> {
        let proxy = reqwest::Proxy::all(format!(
            "socks5h://{}:{}@127.0.0.1:{}",
            helper.user, helper.password, helper.port
        ))?;
        let mut builder = reqwest::blocking::Client::builder()
            .no_proxy()
            .proxy(proxy)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(settings.timeout_seconds))
            .timeout(Duration::from_secs(settings.timeout_seconds))
            .user_agent("xray-tui-health/0.1");
        if let Some(path) = &settings.ca_certificate {
            builder =
                builder.add_root_certificate(reqwest::Certificate::from_pem(&fs::read(path)?)?);
        }
        let client = builder.build()?;
        let response = match client
            .get(&target.url)
            .header("Cache-Control", "no-cache")
            .send()
        {
            Ok(response) => response,
            Err(e) => {
                let log = fs::read_to_string(&helper.log).unwrap_or_default();
                (r.stage, r.detail) = error_category(&e, &log);
                return Ok(());
            }
        };
        r.status = Some(response.status().as_u16());
        if r.status != Some(target.status) {
            r.stage = Stage::Http;
            r.detail = format!(
                "Expected HTTP {}, received {}",
                target.status,
                r.status.unwrap()
            );
            return Ok(());
        }
        let mut body = Vec::new();
        match response
            .take(target.max_bytes as u64 + 1)
            .read_to_end(&mut body)
        {
            Ok(_) => (),
            Err(e) => {
                r.stage = if e.kind() == std::io::ErrorKind::TimedOut {
                    Stage::Timeout
                } else {
                    Stage::Body
                };
                r.detail =
                    "Response headers arrived, but reading the body failed or timed out".into();
                return Ok(());
            }
        }
        r.bytes = body.len();
        if body.len() < target.min_bytes || body.len() > target.max_bytes {
            r.stage = Stage::Body;
            r.detail = format!(
                "Body size {} B outside expected {}..{} B",
                body.len(),
                target.min_bytes,
                target.max_bytes
            );
        } else if let Some(needle) = &target.contains
            && !String::from_utf8_lossy(&body).contains(needle)
        {
            r.stage = Stage::Body;
            r.detail = "Expected body content is missing".into();
        }
        cancelled(flag)?;
        Ok(())
    })();
    if work.is_err() {
        r.stage = if flag.load(Ordering::Relaxed) {
            Stage::Cancelled
        } else {
            Stage::Config
        };
        r.detail = "Could not build the HTTPS probe client, or probe was cancelled".into();
    }
    if flag.load(Ordering::Relaxed) {
        r.stage = Stage::Cancelled;
        r.detail = "Cancelled".into();
    }
    r.elapsed_ms = started.elapsed().as_millis() as u64;
    r
}

pub(super) fn execute(
    doc: &Document,
    entry: &Entry,
    settings: &Settings,
    service: &Service,
    extended: bool,
    flag: &AtomicBool,
) -> Sample {
    let origin = origin(doc, entry);
    let mut sample = Sample {
        at: now(),
        origin,
        extended,
        targets: Vec::new(),
    };
    if let Err(error) = settings
        .validate()
        .and_then(|_| profile(doc, entry, 1, "validate", "validate").map(|_| ()))
    {
        sample.targets.push(TargetResult {
            name: "Configuration".into(),
            stage: Stage::Config,
            elapsed_ms: 0,
            bytes: 0,
            status: None,
            detail: error.to_string(),
        });
        return sample;
    }
    let rounds = if extended { 3 } else { 1 };
    for round in 0..rounds {
        let helper = match Helper::start(doc, entry, service, flag) {
            Ok(helper) => helper,
            Err(error) => {
                sample.targets.push(TargetResult {
                    name: "Isolated Xray".into(),
                    stage: if flag.load(Ordering::Relaxed) {
                        Stage::Cancelled
                    } else {
                        Stage::Startup
                    },
                    elapsed_ms: 0,
                    bytes: 0,
                    status: None,
                    detail: format!("{error:#}"),
                });
                return sample;
            }
        };
        for target in &settings.targets {
            let mut result = request(target, &helper, settings, flag);
            if extended {
                result.name = format!("{} · connection {}", result.name, round + 1);
            }
            let stop = result.stage == Stage::Cancelled;
            sample.targets.push(result);
            if stop {
                return sample;
            }
        }
        if extended && round + 1 == rounds {
            sample
                .targets
                .push(request(&settings.extended_target, &helper, settings, flag));
        }
    }
    sample.at = now();
    sample
}
