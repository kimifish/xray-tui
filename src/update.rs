use crate::{
    config::{atomic_write, backup},
    import::{client, download},
    service::Service,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Cursor, Read, Write},
    os::unix::fs::PermissionsExt,
};

pub struct Release {
    pub version: String,
    pub url: String,
    pub asset: String,
    pub digest_url: String,
}

pub struct PreparedUpdate {
    pub version: String,
    pub sha256: String,
    pub directory: tempfile::TempDir,
}

pub fn latest() -> Result<Release> {
    let release: Value = client()?
        .get("https://api.github.com/repos/XTLS/Xray-core/releases/latest")
        .send()
        .map_err(|e| e.without_url())?
        .error_for_status()
        .map_err(|e| e.without_url())?
        .json()?;
    let arch = match std::env::consts::ARCH {
        "x86_64" => "64",
        "aarch64" => "arm64-v8a",
        "x86" => "32",
        "riscv64" => "riscv64",
        other => bail!("Unsupported update architecture: {other}"),
    };
    let asset = format!("Xray-linux-{arch}.zip");
    let assets = release["assets"]
        .as_array()
        .context("Release has no assets")?;
    let find = |name: &str| -> Result<String> {
        let url = assets
            .iter()
            .find(|a| a["name"].as_str() == Some(name))
            .and_then(|a| a["browser_download_url"].as_str())
            .context("Official release asset missing")?;
        ensure!(
            url.starts_with("https://github.com/XTLS/Xray-core/releases/download/"),
            "Unexpected release asset origin"
        );
        Ok(url.into())
    };
    Ok(Release {
        version: release["tag_name"]
            .as_str()
            .context("Missing release version")?
            .into(),
        url: find(&asset)?,
        digest_url: find(&format!("{asset}.dgst"))?,
        asset,
    })
}

pub fn verify_checksum(bytes: &[u8], digest: &str) -> Result<String> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    let expected: Vec<_> = digest
        .split(|c: char| !c.is_ascii_hexdigit())
        .filter(|s| s.len() == 64)
        .collect();
    ensure!(
        expected.iter().any(|s| s.eq_ignore_ascii_case(&actual)),
        "Official archive SHA-256 mismatch or missing SHA-256 digest"
    );
    Ok(actual)
}

pub fn prepare(release: &Release, service: &Service) -> Result<PreparedUpdate> {
    ensure!(!service.demo, "Updates disabled in demo mode");
    let archive =
        download(&release.url, 80 * 1024 * 1024).context("Downloading official Xray archive")?;
    let digest = String::from_utf8(
        download(&release.digest_url, 16 * 1024).context("Downloading official Xray checksums")?,
    )?;
    prepare_archive(release, service, &archive, &digest)
}

fn prepare_archive(
    release: &Release,
    service: &Service,
    archive: &[u8],
    digest: &str,
) -> Result<PreparedUpdate> {
    let hash = verify_checksum(archive, digest)?;
    let mut zip = zip::ZipArchive::new(Cursor::new(archive))?;
    let entry = zip
        .by_name("xray")
        .context("Archive contains no xray binary")?;
    ensure!(
        entry.size() <= 160 * 1024 * 1024,
        "Binary exceeds size limit"
    );
    let directory = tempfile::Builder::new()
        .prefix(".xray-update-")
        .tempdir_in(service.binary.parent().unwrap())?;
    let mut bytes = Vec::new();
    entry.take(160 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 160 * 1024 * 1024,
        "Binary exceeds size limit"
    );
    let path = directory.path().join("xray");
    let mut file = fs::File::create(&path)?;
    file.set_permissions(fs::Permissions::from_mode(0o700))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    // Linux refuses execve while any writable descriptor still refers to the executable.
    drop(file);
    service
        .test(&fs::read_to_string(&service.config)?, Some(&path))
        .context("Validating downloaded Xray against the saved configuration")?;
    Ok(PreparedUpdate {
        version: release.version.clone(),
        sha256: hash,
        directory,
    })
}

pub fn install(update: PreparedUpdate, service: &Service) -> Result<String> {
    ensure!(!service.demo, "Updates disabled in demo mode");
    let candidate = update.directory.path().join("xray");
    // Revalidate against current config, even if it changed after the download.
    service.test(&fs::read_to_string(&service.config)?, Some(&candidate))?;
    let before = fs::read(&service.binary)?;
    let bytes = fs::read(candidate)?;
    let active = service.status()?.active;
    ensure!(
        ["active", "inactive", "failed"].contains(&active.as_str()),
        "Service is transitioning; try again once stable"
    );
    let saved = backup(&service.binary)?;
    let mode = fs::metadata(&service.binary)?.permissions().mode() & 0o777;
    ensure!(
        fs::read(&service.binary)? == before,
        "Binary changed externally; update cancelled"
    );
    atomic_write(&service.binary, &bytes, mode)?;
    if active == "active"
        && let Err(error) = service.action("restart")
    {
        ensure!(
            fs::read(&service.binary)? == bytes,
            "Update failed ({error}); binary changed externally; rollback skipped. Backup: {}",
            saved.display()
        );
        atomic_write(&service.binary, &before, mode)?;
        match service.action("restart") {
            Ok(_) => bail!(
                "Update failed ({error}); old binary and service restored. Backup: {}",
                saved.display()
            ),
            Err(recovery) => bail!(
                "Update failed ({error}); old binary restored, service recovery failed: {recovery}. Backup: {}",
                saved.display()
            ),
        }
    }
    Ok(format!(
        "Installed {}{} · binary backup: {}",
        update.version,
        if active == "active" {
            "; service restarted"
        } else {
            "; service remains stopped"
        },
        saved.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::{ZipWriter, write::SimpleFileOptions};

    #[test]
    fn extracted_binary_can_execute_before_installation() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config.jsonc");
        fs::write(
            &config,
            "{\"outbounds\":[{\"tag\":\"direct\",\"protocol\":\"freedom\"}]}",
        )
        .unwrap();
        let binary = root.path().join("xray");
        fs::write(&binary, "installed binary must remain untouched").unwrap();
        let service = Service {
            unit: "test.service".into(),
            user: true,
            binary: binary.clone(),
            config: config.clone(),
            working_dir: root.path().into(),
            demo: false,
            controller: root.path().join("must-not-run-systemctl"),
        };
        let release = Release {
            version: "test".into(),
            url: String::new(),
            asset: "test.zip".into(),
            digest_url: String::new(),
        };
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file("xray", SimpleFileOptions::default())
            .unwrap();
        // Record that the real process successfully executed the freshly extracted candidate.
        zip.write_all(b"#!/bin/sh\n[ \"$1 $2 $3\" = \"run -test -c\" ] || exit 2\ntest -f \"$4\" || exit 3\nprintf checked > candidate-tested\n").unwrap();
        let archive = zip.finish().unwrap().into_inner();
        let digest = format!("SHA256={:x}", Sha256::digest(&archive));
        let update = prepare_archive(&release, &service, &archive, &digest).unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("candidate-tested")).unwrap(),
            "checked"
        );
        assert!(update.directory.path().join("xray").is_file());
        assert_eq!(
            fs::read_to_string(&binary).unwrap(),
            "installed binary must remain untouched"
        );
        assert_eq!(
            fs::read_to_string(&config).unwrap(),
            "{\"outbounds\":[{\"tag\":\"direct\",\"protocol\":\"freedom\"}]}"
        );
        let staging = update.directory.path().to_path_buf();
        drop(update);
        assert!(!staging.exists());
    }
}
