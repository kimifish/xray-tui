//! Offline HTTPS + real Xray integration. Opt in with XRAY_TEST_BINARY=/path/to/xray.
use clap::Parser;
use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};
use xray_tui::{
    config::Document,
    health::{self, Settings, Stage, Target},
    service::{Options, Service},
};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn setup() -> Option<(tempfile::TempDir, Server, Document, Service, Settings)> {
    let binary = std::env::var_os("XRAY_TEST_BINARY").map(PathBuf::from)?;
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let ca = dir.path().join("ca.pem");
    let ca_key = dir.path().join("ca.key");
    let csr = dir.path().join("server.csr");
    let extensions = dir.path().join("server.ext");
    fs::write(&extensions,"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n").unwrap();
    let openssl = |args: &[&str]| {
        assert!(
            Command::new("openssl")
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        )
    };
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=Probe Test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-keyout",
        ca_key.to_str().unwrap(),
        "-out",
        ca.to_str().unwrap(),
    ]);
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=localhost",
        "-keyout",
        key.to_str().unwrap(),
        "-out",
        csr.to_str().unwrap(),
    ]);
    openssl(&[
        "x509",
        "-req",
        "-days",
        "1",
        "-in",
        csr.to_str().unwrap(),
        "-CA",
        ca.to_str().unwrap(),
        "-CAkey",
        ca_key.to_str().unwrap(),
        "-CAcreateserial",
        "-out",
        cert.to_str().unwrap(),
        "-extfile",
        extensions.to_str().unwrap(),
    ]);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let script = r#"
import http.server,ssl,sys,time
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path=='/slow':time.sleep(5)
  body=b'a'*524288 if self.path=='/large' else (b'x' if self.path=='/short' else b'probe-ok:local-test')
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
  try:self.wfile.write(body)
  except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
 def log_message(self,*args):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',int(sys.argv[1])),Handler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(sys.argv[2],sys.argv[3]);server.socket=ctx.wrap_socket(server.socket,server_side=True)
server.serve_forever()
"#;
    let child = Command::new("python3")
        .args(["-c", script, &port.to_string()])
        .arg(&cert)
        .arg(&key)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let server = Server(child);
    let mut ready = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    assert!(ready);
    let config = dir.path().join("config.jsonc");
    // Default deliberately blocks: only the forced probe inbound -> direct rule can pass.
    fs::write(&config,r#"{"outbounds":[{"tag":"blocked-default","protocol":"blackhole"},{"tag":"local-direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","network":"tcp","outboundTag":"blocked-default"}]}}"#).unwrap();
    let args = vec![
        "xray-tui".to_string(),
        "--binary".into(),
        binary.to_string_lossy().into_owned(),
        "--config".into(),
        config.to_string_lossy().into_owned(),
    ];
    let service = Service::discover(&Options::parse_from(args)).unwrap();
    let doc = Document::load(&config).unwrap();
    let target = Target {
        name: "local TLS".into(),
        url: format!("https://127.0.0.1:{port}/ok"),
        status: 200,
        contains: Some("probe-ok".into()),
        min_bytes: 8,
        max_bytes: 1024,
    };
    let settings = Settings {
        ca_certificate: Some(ca),
        timeout_seconds: 2,
        targets: vec![
            target.clone(),
            Target {
                name: "second connection".into(),
                ..target
            },
        ],
        extended_target: Target {
            name: "512 KiB".into(),
            url: format!("https://127.0.0.1:{port}/large"),
            status: 200,
            contains: None,
            min_bytes: 524288,
            max_bytes: 524288,
        },
        ..Settings::default()
    };
    Some((dir, server, doc, service, settings))
}

#[test]
fn real_core_probes_tls_status_body_extended_and_cleanup_without_restarting_service() {
    let Some((_dir, _server, doc, service, mut settings)) = setup() else {
        eprintln!("Set XRAY_TEST_BINARY to run offline HTTPS/core integration");
        return;
    };
    let entry = doc.entries("outbounds").unwrap().remove(1);
    let original = fs::read(&doc.path).unwrap();
    let sample = health::check(&doc, &entry, &settings, &service, false).unwrap();
    assert!(sample.all_ok(), "{sample:?}");
    let sample = health::check(&doc, &entry, &settings, &service, true).unwrap();
    assert!(sample.all_ok(), "{sample:?}");
    assert_eq!(sample.targets.len(), 7);
    assert_eq!(sample.targets.last().unwrap().bytes, 524288);
    settings.targets[0].status = 204;
    let sample = health::check(&doc, &entry, &settings, &service, false).unwrap();
    assert_eq!(sample.targets[0].stage, Stage::Http);
    assert_eq!(sample.successes(), 1);
    settings.targets[0].status = 200;
    settings.targets[0].contains = Some("not-present".into());
    let sample = health::check(&doc, &entry, &settings, &service, false).unwrap();
    assert_eq!(sample.targets[0].stage, Stage::Body);
    settings.targets[0].contains = Some("probe-ok".into());
    let trusted = settings.ca_certificate.clone();
    settings.ca_certificate = None;
    let sample = health::check(&doc, &entry, &settings, &service, false).unwrap();
    assert!(!sample.all_ok());
    assert_eq!(sample.targets[0].stage, Stage::Tls, "{sample:?}");
    settings.ca_certificate = trusted;
    settings.targets[0].url = settings.targets[0].url.replace("/ok", "/large");
    let sample = health::check(&doc, &entry, &settings, &service, false).unwrap();
    assert_eq!(sample.targets[0].stage, Stage::Body);
    assert_eq!(sample.targets[0].bytes, 1025);
    settings.targets[0].url = settings.targets[0].url.replace("/large", "/slow");
    let sample = health::check(&doc, &entry, &settings, &service, false).unwrap();
    assert_eq!(sample.targets[0].stage, Stage::Timeout, "{sample:?}");
    // Closing the UI/monitor cancels work and reaps its real helper process.
    let demo = Service::discover(&Options::parse_from(["xray-tui", "--demo"])).unwrap();
    let mut monitor = health::Monitor::new(&demo);
    settings.enabled = false;
    monitor
        .enqueue(&doc, &entry, &settings, &service, false)
        .unwrap();
    monitor.tick(&service, &settings, false);
    thread::sleep(Duration::from_millis(150));
    let closing = std::time::Instant::now();
    drop(monitor);
    assert!(closing.elapsed() < Duration::from_secs(4));
    let self_pid = std::process::id();
    for proc in fs::read_dir("/proc").unwrap().filter_map(Result::ok) {
        if fs::read_to_string(proc.path().join("comm"))
            .ok()
            .is_some_and(|s| s.trim() == "xray")
        {
            let status = fs::read_to_string(proc.path().join("status")).unwrap_or_default();
            assert!(
                !status.lines().any(|line| line
                    .strip_prefix("PPid:")
                    .is_some_and(|v| v.trim() == self_pid.to_string())),
                "helper process left alive after cancellation"
            );
        }
    }
    assert_eq!(fs::read(&doc.path).unwrap(), original);
}
