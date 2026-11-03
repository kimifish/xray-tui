use crate::config::{Document, Subscription, parse};
use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use std::{collections::HashMap, io::Read, time::Duration};
use url::Url;

pub fn decode(s: &str) -> Result<String> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(&compact) {
            return String::from_utf8(bytes).context("Base64 is not UTF-8");
        }
    }
    bail!("Invalid base64")
}

fn percent(s: &str) -> String {
    // URL form parsing provides percent decoding; preserve literal '+' in credentials/names.
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

pub fn parse_nodes(text: &str) -> Result<Vec<Value>> {
    let text = text.trim().trim_start_matches('\u{feff}');
    if text.starts_with('{') || text.starts_with('[') {
        let value = parse(text)?;
        let nodes = if let Some(a) = value.as_array() {
            a.clone()
        } else if let Some(a) = value["outbounds"].as_array() {
            a.clone()
        } else {
            vec![value]
        };
        ensure!(!nodes.is_empty(), "No outbounds found");
        for node in &nodes {
            ensure!(
                node.is_object() && node["protocol"].is_string(),
                "Every outbound needs a protocol"
            );
        }
        return Ok(nodes);
    }
    let decoded;
    let text = if !text.contains("://") {
        decoded = decode(text)?;
        decoded.trim()
    } else {
        text
    };
    let mut nodes = Vec::new();
    for (i, line) in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
    {
        nodes.push(parse_uri(line).with_context(|| {
            format!(
                "Unsupported/invalid node at line {} (no changes imported)",
                i + 1
            )
        })?);
    }
    ensure!(
        !nodes.is_empty(),
        "Subscription contains no supported nodes"
    );
    Ok(nodes)
}

pub fn parse_uri(uri: &str) -> Result<Value> {
    if let Some(encoded) = uri.strip_prefix("vmess://") {
        let v: Value = serde_json::from_str(&decode(encoded)?)?;
        let port = v["port"]
            .as_u64()
            .or_else(|| v["port"].as_str().and_then(|p| p.parse().ok()))
            .context("VMess port missing")?;
        ensure!((1..=65535).contains(&port), "Invalid port");
        let host = v["add"]
            .as_str()
            .filter(|s| !s.is_empty())
            .context("VMess host missing")?;
        let id = v["id"].as_str().context("VMess ID missing")?;
        let mut node = json!({"tag":v["ps"].as_str().filter(|s| !s.is_empty()).unwrap_or(host),"protocol":"vmess","settings":{"vnext":[{"address":host,"port":port,"users":[{"id":id,"alterId":v["aid"].as_u64().or_else(||v["aid"].as_str().and_then(|s|s.parse().ok())).unwrap_or(0),"security":v["scy"].as_str().unwrap_or("auto")}]}]}});
        let mut q = HashMap::new();
        for (key, from) in [
            ("type", "net"),
            ("security", "tls"),
            ("sni", "sni"),
            ("host", "host"),
            ("path", "path"),
            ("fp", "fp"),
            ("alpn", "alpn"),
        ] {
            if let Some(s) = v[from].as_str().filter(|s| !s.is_empty()) {
                q.insert(key.to_string(), s.to_string());
            }
        }
        if q.get("security").is_some_and(|s| s == "none") {
            q.remove("security");
        }
        node["streamSettings"] = stream(&q, host)?;
        return Ok(node);
    }
    let url = Url::parse(uri).context("Invalid share link")?;
    let protocol = url.scheme();
    ensure!(
        ["vless", "trojan", "ss", "socks", "socks5", "http", "https"].contains(&protocol),
        "Unsupported protocol: {protocol}"
    );
    let mut q: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let host = url
        .host_str()
        .context("Missing server address")?
        .trim_matches(['[', ']']);
    let port = url.port_or_known_default().context("Missing server port")?;
    let tag = url
        .fragment()
        .map(percent)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{protocol}-{host}-{port}"));
    let user = percent(url.username());
    let settings = match protocol {
        "vless" => {
            ensure!(!user.is_empty(), "VLESS ID missing");
            json!({"vnext":[{"address":host,"port":port,"users":[{"id":user,"encryption":q.remove("encryption").unwrap_or_else(||"none".into()),"flow":q.remove("flow").unwrap_or_default()}]}]})
        }
        "trojan" => {
            ensure!(!user.is_empty(), "Trojan password missing");
            q.entry("security".into()).or_insert("tls".into());
            json!({"servers":[{"address":host,"port":port,"password":user}]})
        }
        "ss" => {
            ensure!(
                !q.contains_key("plugin"),
                "Shadowsocks plugins are not supported"
            );
            let credentials = if let Some(password) = url.password() {
                format!("{user}:{}", percent(password))
            } else {
                decode(&user)?
            };
            let (method, password) = credentials
                .split_once(':')
                .context("Invalid Shadowsocks credentials")?;
            json!({"servers":[{"address":host,"port":port,"method":method,"password":password}]})
        }
        _ => {
            let mut server = json!({"address":host,"port":port});
            if !user.is_empty() {
                server["users"] =
                    json!([{"user":user,"pass":url.password().map(percent).unwrap_or_default()}]);
            }
            if protocol == "https" {
                q.insert("security".into(), "tls".into());
            }
            json!({"servers":[server]})
        }
    };
    let core_protocol = match protocol {
        "ss" => "shadowsocks",
        "socks5" => "socks",
        "https" => "http",
        other => other,
    };
    Ok(
        json!({"tag":tag,"protocol":core_protocol,"settings":settings,"streamSettings":stream(&q,host)?}),
    )
}

fn stream(q: &HashMap<String, String>, host: &str) -> Result<Value> {
    let get = |key: &str, default: &str| q.get(key).cloned().unwrap_or_else(|| default.into());
    let network = get("type", "tcp");
    let security = get("security", "none");
    ensure!(
        [
            "tcp",
            "raw",
            "ws",
            "grpc",
            "httpupgrade",
            "xhttp",
            "splithttp"
        ]
        .contains(&network.as_str()),
        "Unsupported transport: {network}"
    );
    ensure!(
        ["none", "tls", "reality"].contains(&security.as_str()),
        "Unsupported security: {security}"
    );
    ensure!(
        !q.contains_key("allowInsecure") && !q.contains_key("insecure"),
        "Insecure TLS share links require manual JSON review"
    );
    let mut s = json!({"network":network,"security":security});
    let server_name = get("sni", &get("serverName", host));
    if security == "tls" {
        s["tlsSettings"] = json!({"serverName":server_name,"fingerprint":get("fp","chrome")});
        if let Some(alpn) = q.get("alpn") {
            s["tlsSettings"]["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
        }
    } else if security == "reality" {
        let pbk = q
            .get("pbk")
            .filter(|s| !s.is_empty())
            .context("Reality public key (pbk) missing")?;
        s["realitySettings"] = json!({"serverName":server_name,"fingerprint":get("fp","chrome"),"publicKey":pbk,"shortId":get("sid",""),"spiderX":get("spx","")});
    }
    match network.as_str() {
        "ws" => {
            s["wsSettings"] = json!({"path":get("path","/"),"headers":{"Host":get("host",host)}})
        }
        "grpc" => {
            s["grpcSettings"] = json!({"serviceName":get("serviceName",&get("path","")),"multiMode":get("mode","gun") == "multi"})
        }
        "httpupgrade" => {
            s["httpupgradeSettings"] = json!({"path":get("path","/"),"host":get("host",host)})
        }
        "xhttp" | "splithttp" => {
            s["network"] = json!("xhttp");
            s["xhttpSettings"] =
                json!({"path":get("path","/"),"host":get("host",host),"mode":get("mode","auto")});
            if let Some(extra) = q.get("extra") {
                s["xhttpSettings"]["extra"] =
                    serde_json::from_str(extra).context("Invalid XHTTP extra JSON")?;
            }
        }
        "tcp" | "raw" => {
            ensure!(
                get("headerType", "none") == "none",
                "TCP HTTP camouflage needs manual JSON import"
            );
        }
        _ => (),
    }
    Ok(s)
}

pub fn client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .user_agent("xray-tui/0.1")
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()?)
}

pub fn download(url: &str, limit: u64) -> Result<Vec<u8>> {
    let parsed = Url::parse(url).context("Invalid URL")?;
    ensure!(parsed.scheme() == "https", "Only HTTPS URLs are supported");
    let mut body = Vec::new();
    client()?
        .get(url)
        .send()
        .map_err(|e| e.without_url())?
        .error_for_status()
        .map_err(|e| e.without_url())?
        .take(limit + 1)
        .read_to_end(&mut body)?;
    ensure!(body.len() as u64 <= limit, "Download exceeds size limit");
    Ok(body)
}

pub fn fetch_subscription(url: &str) -> Result<Vec<Value>> {
    parse_nodes(
        &String::from_utf8(download(url, 8 * 1024 * 1024)?).context("Subscription is not UTF-8")?,
    )
}

// Transactional merge: only this subscription's tags may be replaced. Removed server nodes
// stay in place while a rule or chain references them. Disabled nodes remain disabled.
pub fn merge_subscription(
    doc: &Document,
    mut sub: Subscription,
    nodes: &[Value],
) -> Result<(Document, String)> {
    ensure!(!sub.name.trim().is_empty(), "Subscription name is required");
    let mut draft = doc.clone();
    let old = doc.meta.subscriptions.iter().find(|s| s.name == sub.name);
    let owned = old.map(|s| s.tags.clone()).unwrap_or_default();
    let mut tags = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let mut node = node.clone();
        let name = node["tag"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("node-{}", i + 1));
        let base = format!("{} / {name}", sub.name);
        let mut tag = base.clone();
        let mut n = 2;
        while tags.contains(&tag) {
            tag = format!("{base} ({n})");
            n += 1;
        }
        node["tag"] = json!(tag);
        let existing = draft
            .entries("outbounds")?
            .into_iter()
            .find(|e| e.value["tag"].as_str() == Some(&tag));
        ensure!(
            existing.is_none() || owned.contains(&tag),
            "Tag '{tag}' belongs to a manual node or another subscription"
        );
        draft.put(
            "outbounds",
            existing.as_ref(),
            &serde_json::to_string_pretty(&node)?,
        )?;
        tags.push(tag);
    }
    let mut retained = 0;
    let removed: Vec<_> = owned
        .iter()
        .filter(|tag| !tags.contains(tag))
        .cloned()
        .collect();
    for tag in &removed {
        if let Some(entry) = draft
            .entries("outbounds")?
            .into_iter()
            .find(|e| e.value["tag"].as_str() == Some(tag))
            && draft.delete("outbounds", &entry).is_err()
        {
            tags.push(tag.clone());
            retained += 1;
        }
    }
    sub.tags = tags;
    sub.updated = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    );
    if let Some(i) = draft
        .meta
        .subscriptions
        .iter()
        .position(|s| s.name == sub.name)
    {
        draft.meta.subscriptions[i] = sub;
    } else {
        draft.meta.subscriptions.push(sub);
    }
    Ok((
        draft,
        format!(
            "{} nodes merged into draft; {retained} referenced/default nodes retained",
            nodes.len()
        ),
    ))
}
