use crate::config::{Document, atomic_write, backup};
use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Parser, Clone, Debug)]
#[command(
    version,
    about = "Xray terminal control panel. Opening the UI never changes the running service."
)]
pub struct Options {
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub binary: Option<PathBuf>,
    #[arg(long, default_value = "xray.service")]
    pub service: String,
    /// Manage the system service instead of the automatically detected user service
    #[arg(long)]
    pub system: bool,
    /// Open an isolated example with service and network actions disabled
    #[arg(long)]
    pub demo: bool,
    /// Validate config with the installed Xray, without changing files or service state
    #[arg(long)]
    pub check: bool,
    /// Show the latest official stable release without downloading or installing it
    #[arg(long)]
    pub check_update: bool,
    /// Check one outbound through an isolated Xray without changing the service
    #[arg(long, conflicts_with = "probe_all")]
    pub probe: Option<String>,
    /// Check all enabled web outbounds once, without entering the TUI
    #[arg(long)]
    pub probe_all: bool,
    /// Use three fresh connections per target and a bounded transfer test
    #[arg(long)]
    pub extended: bool,
    /// Render a single UI frame to an SVG file, without entering the terminal UI
    #[arg(long)]
    pub snapshot: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::{self, PreparedUpdate};
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, Service, Document) {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("xray");
        fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let config = dir.path().join("config.jsonc");
        fs::write(
            &config,
            "{\"outbounds\":[{\"tag\":\"direct\",\"protocol\":\"freedom\"}]}\n",
        )
        .unwrap();
        let controller = dir.path().join("systemctl");
        // The first restart fails, simulating a core that exits on startup. Recovery succeeds.
        fs::write(&controller,r#"#!/bin/sh
root=$(dirname "$0")
case " $* " in
  *" show "*) printf 'ActiveState=active\nSubState=running\nMainPID=123\nMemoryCurrent=0\n';;
  *" restart "*) if [ ! -f "$root/restarted" ]; then touch "$root/restarted"; echo simulated-startup-failure >&2; exit 1; fi;;
esac
"#).unwrap();
        fs::set_permissions(&controller, fs::Permissions::from_mode(0o700)).unwrap();
        let s = Service {
            unit: "test.service".into(),
            user: true,
            binary,
            config: config.clone(),
            working_dir: dir.path().into(),
            demo: false,
            controller,
        };
        let d = Document::load(&config).unwrap();
        (dir, s, d)
    }

    #[test]
    fn apply_failure_restores_original_file_and_running_service() {
        let (_dir, s, mut d) = fixture();
        d.set_section("log", r#"{"loglevel":"warning"}"#).unwrap();
        let error = s.save(&d, true).unwrap_err().to_string();
        assert!(
            error.contains("previous config and service restored"),
            "{error}"
        );
        assert_eq!(fs::read_to_string(&s.config).unwrap(), d.original);
    }

    #[test]
    fn save_detects_external_edit_and_makes_no_changes() {
        let (_dir, s, mut d) = fixture();
        d.set_section("log", r#"{"loglevel":"warning"}"#).unwrap();
        fs::write(&s.config, "{\"external\":true}").unwrap();
        assert!(
            s.save(&d, false)
                .unwrap_err()
                .to_string()
                .contains("changed on disk")
        );
        assert_eq!(
            fs::read_to_string(&s.config).unwrap(),
            "{\"external\":true}"
        );
    }

    #[test]
    fn save_without_apply_keeps_service_and_creates_private_backup() {
        let (dir, s, mut d) = fixture();
        d.set_section("log", r#"{"loglevel":"warning"}"#).unwrap();
        let (saved, message) = s.save(&d, false).unwrap();
        assert_eq!(fs::read_to_string(&s.config).unwrap(), saved);
        assert!(message.contains("restart to apply"));
        assert!(!dir.path().join("restarted").exists());
        let backups: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|p| p.file_name().to_string_lossy().contains("backup-"))
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read_to_string(backups[0].path()).unwrap(), d.original);
    }

    #[test]
    fn failed_core_upgrade_rolls_binary_back() {
        let (_dir, s, _d) = fixture();
        let original = fs::read(&s.binary).unwrap();
        let directory = tempfile::tempdir_in(s.binary.parent().unwrap()).unwrap();
        let candidate = directory.path().join("xray");
        fs::write(&candidate, "#!/bin/sh\n# candidate\nexit 0\n").unwrap();
        fs::set_permissions(candidate, fs::Permissions::from_mode(0o700)).unwrap();
        let update = PreparedUpdate {
            version: "test".into(),
            sha256: "test".into(),
            directory,
        };
        let error = update::install(update, &s).unwrap_err().to_string();
        assert!(error.contains("old binary and service restored"), "{error}");
        assert_eq!(fs::read(&s.binary).unwrap(), original);
        assert_eq!(
            fs::metadata(&s.binary).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[derive(Clone, Debug)]
pub struct Service {
    pub(crate) controller: PathBuf,
    pub unit: String,
    pub user: bool,
    pub binary: PathBuf,
    pub config: PathBuf,
    pub working_dir: PathBuf,
    pub demo: bool,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub active: String,
    pub sub: String,
    pub pid: String,
    pub memory: String,
    pub version: String,
}

pub fn run(command: &mut Command, timeout: Duration) -> Result<String> {
    let program = command.get_program().to_string_lossy().into_owned();
    // File-backed capture avoids pipe deadlocks and bounds wall time for child processes.
    let mut out = tempfile::tempfile()?;
    let mut err = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(err.try_clone()?)
        .spawn()
        .with_context(|| format!("Cannot execute {program}"))?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Command timed out after {}s", timeout.as_secs());
        }
        thread::sleep(Duration::from_millis(25));
    };
    use std::io::{Seek, SeekFrom};
    out.seek(SeekFrom::Start(0))?;
    err.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    out.take(128 * 1024).read_to_string(&mut text)?;
    err.take(128 * 1024).read_to_string(&mut text)?;
    ensure!(
        status.success(),
        "{program} failed ({status}): {}",
        if text.trim().is_empty() {
            "no diagnostic output"
        } else {
            text.trim()
        }
    );
    Ok(text.trim().to_owned())
}

fn property(text: &str, name: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{name}=")))
        .unwrap_or("")
        .to_owned()
}

impl Service {
    fn ctl(&self) -> Command {
        let mut c = Command::new(&self.controller);
        if self.user {
            c.arg("--user");
        }
        c.arg("--no-pager").arg("--no-ask-password");
        c
    }

    pub fn discover(options: &Options) -> Result<Self> {
        ensure!(
            !options.service.starts_with('-') && !options.service.contains('/'),
            "Invalid systemd unit name"
        );
        if options.demo {
            return Ok(Self {
                unit: options.service.clone(),
                user: true,
                binary: "/demo/xray".into(),
                config: "/demo/config.jsonc".into(),
                working_dir: "/demo".into(),
                demo: true,
                controller: "systemctl".into(),
            });
        }
        let mut s = Self {
            unit: options.service.clone(),
            user: !options.system,
            binary: PathBuf::new(),
            config: PathBuf::new(),
            working_dir: PathBuf::new(),
            demo: false,
            controller: "systemctl".into(),
        };
        let show = |s: &Self| {
            run(
                s.ctl().args([
                    "show",
                    &s.unit,
                    "-p",
                    "LoadState",
                    "-p",
                    "MainPID",
                    "-p",
                    "ExecStart",
                    "-p",
                    "WorkingDirectory",
                ]),
                Duration::from_secs(5),
            )
        };
        let mut info = show(&s).unwrap_or_default();
        if !options.system && property(&info, "LoadState") != "loaded" {
            s.user = false;
            info = show(&s)?;
        }
        let pid = property(&info, "MainPID");
        let args: Vec<String> = fs::read(format!("/proc/{pid}/cmdline"))
            .ok()
            .map(|b| {
                b.split(|b| *b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        // For stopped services, systemd exposes a structured ExecStart. Extract argv[] then
        // parse with shell quoting rules. Unsupported/multi-file installations require flags.
        let exec = property(&info, "ExecStart");
        let fallback = exec
            .split("argv[]=")
            .nth(1)
            .and_then(|s| s.split(" ;").next())
            .and_then(|s| shell_words::split(s).ok())
            .unwrap_or_default();
        let args = if args.is_empty() { fallback } else { args };
        s.working_dir = property(&info, "WorkingDirectory").into();
        if s.working_dir.as_os_str().is_empty() {
            s.working_dir = std::env::current_dir()?;
        }
        s.binary = options
            .binary
            .clone()
            .or_else(|| args.first().map(PathBuf::from))
            .context("Cannot detect Xray binary. Supply --binary PATH")?;
        let configs: Vec<_> = args
            .iter()
            .enumerate()
            .filter_map(|(i, a)| {
                if ["-c", "-config", "--config"].contains(&a.as_str()) {
                    args.get(i + 1).map(PathBuf::from)
                } else {
                    a.strip_prefix("-c=")
                        .or_else(|| a.strip_prefix("-config="))
                        .or_else(|| a.strip_prefix("--config="))
                        .map(PathBuf::from)
                }
            })
            .collect();
        ensure!(
            options.config.is_some()
                || (configs.len() == 1 && !args.iter().any(|a| a.starts_with("-confdir"))),
            "Multi-file/unknown configuration: supply --config PATH explicitly"
        );
        s.config = options
            .config
            .clone()
            .or_else(|| configs.first().cloned())
            .context("Supply --config PATH")?;
        if s.config.is_relative() {
            s.config = s.working_dir.join(&s.config);
        }
        if s.binary.is_relative() {
            s.binary = s.working_dir.join(&s.binary);
        }
        s.binary = s
            .binary
            .canonicalize()
            .context("Cannot resolve Xray binary")?;
        s.config = s
            .config
            .canonicalize()
            .context("Cannot resolve Xray config")?;
        Ok(s)
    }

    pub fn status(&self) -> Result<Status> {
        if self.demo {
            return Ok(Status {
                active: "active".into(),
                sub: "running".into(),
                pid: "24816".into(),
                memory: "42 MiB".into(),
                version: "Xray · demo".into(),
            });
        }
        let info = run(
            self.ctl().args([
                "show",
                &self.unit,
                "-p",
                "ActiveState",
                "-p",
                "SubState",
                "-p",
                "MainPID",
                "-p",
                "MemoryCurrent",
            ]),
            Duration::from_secs(5),
        )?;
        let mem = property(&info, "MemoryCurrent")
            .parse::<u64>()
            .ok()
            .filter(|v| *v < u64::MAX)
            .map(|v| format!("{} MiB", v / 1024 / 1024))
            .unwrap_or_else(|| "—".into());
        Ok(Status {
            active: property(&info, "ActiveState"),
            sub: property(&info, "SubState"),
            pid: property(&info, "MainPID"),
            memory: mem,
            version: String::new(),
        })
    }

    pub fn version(&self) -> Result<String> {
        if self.demo {
            return Ok("Xray · demo".into());
        }
        Ok(run(
            Command::new(&self.binary).arg("version"),
            Duration::from_secs(5),
        )?
        .lines()
        .next()
        .unwrap_or("Unknown version")
        .to_owned())
    }

    pub fn test(&self, text: &str, binary: Option<&Path>) -> Result<()> {
        let d = Document::from_text(self.config.clone(), text.to_owned())?;
        d.validate_structure()?;
        if self.demo {
            return Ok(());
        }
        let mut candidate = tempfile::Builder::new()
            .suffix(".jsonc")
            .tempfile_in(self.config.parent().unwrap())?;
        candidate.write_all(text.as_bytes())?;
        run(
            Command::new(binary.unwrap_or(&self.binary))
                .current_dir(&self.working_dir)
                .env("XRAY_LOCATION_ASSET", self.binary.parent().unwrap())
                .arg("run")
                .arg("-test")
                .arg("-c")
                .arg(candidate.path()),
            Duration::from_secs(20),
        )?;
        Ok(())
    }

    pub fn action(&self, action: &str) -> Result<String> {
        ensure!(!self.demo, "Service actions are disabled in demo mode");
        ensure!(
            ["start", "stop", "restart"].contains(&action),
            "Unsupported service action"
        );
        run(
            self.ctl().args([action, &self.unit]),
            Duration::from_secs(25),
        )?;
        if action != "stop" {
            self.wait_healthy()?;
        } else {
            ensure!(self.status()?.active == "inactive", "Service did not stop");
        }
        Ok(format!("{}: {action} completed", self.unit))
    }

    pub fn wait_healthy(&self) -> Result<()> {
        let mut good = 0;
        for _ in 0..30 {
            let status = self.status()?;
            if status.active == "active" && status.sub == "running" && status.pid != "0" {
                good += 1;
            } else {
                good = 0;
            }
            if good >= 5 {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(250));
        }
        bail!("Xray failed to stay running; inspect journalctl")
    }

    pub fn save(&self, doc: &Document, apply: bool) -> Result<(String, String)> {
        ensure!(!self.demo, "Saving is disabled in demo mode");
        doc.validate_structure()?;
        let rendered = doc.rendered()?;
        self.test(&rendered, None)?;
        ensure!(
            fs::read_to_string(&doc.path)? == doc.original,
            "Config changed on disk. Reload with 'R' before saving; your draft is still open."
        );
        let prior_status = self.status()?;
        ensure!(
            !apply
                || prior_status.active == "active"
                || prior_status.active == "inactive"
                || prior_status.active == "failed",
            "Service is transitioning; try again once stable"
        );
        let saved = backup(&doc.path)?;
        // Check again after validation/backup, immediately before replacement.
        ensure!(
            fs::read_to_string(&doc.path)? == doc.original,
            "Config changed on disk; refusing to overwrite it"
        );
        atomic_write(&doc.path, rendered.as_bytes(), 0o600)?;
        if apply && let Err(error) = self.action("restart") {
            // Do not clobber an external edit made while systemd was restarting.
            if fs::read_to_string(&doc.path)? != rendered {
                bail!(
                    "Apply failed ({error}); config was edited externally, rollback skipped. Backup: {}",
                    saved.display()
                );
            }
            atomic_write(&doc.path, doc.original.as_bytes(), 0o600)?;
            if prior_status.active == "active" {
                match self.action("restart") {
                    Ok(_) => bail!(
                        "Apply failed ({error}); previous config and service restored. Backup: {}",
                        saved.display()
                    ),
                    Err(recovery) => bail!(
                        "Apply failed ({error}); config restored, service recovery failed: {recovery}. Backup: {}",
                        saved.display()
                    ),
                }
            } else {
                let recovery = self.action("stop");
                bail!(
                    "Apply failed ({error}); previous config restored, stop result: {recovery:?}. Backup: {}",
                    saved.display()
                );
            }
        }
        Ok((
            rendered,
            format!(
                "{} · backup: {}",
                if apply {
                    "Saved and applied"
                } else {
                    "Saved; restart to apply"
                },
                saved.display()
            ),
        ))
    }
}
