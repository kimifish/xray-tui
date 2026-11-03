use anyhow::{Context, Result, bail, ensure};
use jsonc_parser::{
    ParseOptions,
    cst::{CstArray, CstInputValue, CstNode, CstObject, CstRootNode},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const META: &str = "// @xray-tui:v1 ";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<crate::health::Settings>,
    #[serde(default)]
    pub disabled: Vec<Disabled>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Disabled {
    pub section: String,
    pub index: usize,
    pub raw: String,
    #[serde(default)]
    pub successors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub updated: Option<u64>,
}

#[derive(Clone)]
pub struct Document {
    pub path: PathBuf,
    pub text: String,
    pub original: String,
    pub meta: Metadata,
    read_cache: RefCell<ReadCache>,
    original_cache: RefCell<Option<(String, Option<Value>)>>,
}

// Store only owned, Send values: documents are also moved to worker threads.
// Compare the source on access because editors and save jobs can assign text directly.
#[derive(Clone, Default)]
struct ReadCache {
    text: String,
    value: Option<Value>,
    entries: HashMap<String, Vec<Entry>>,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub value: Value,
    pub raw: String,
    pub active_index: Option<usize>,
    pub disabled_index: Option<usize>,
}

pub fn parse(text: &str) -> Result<Value> {
    let root = CstRootNode::parse(text, &ParseOptions::default())?;
    root.value()
        .and_then(|v| v.to_serde_value())
        .context("Empty JSONC document")
}

fn input(v: &Value) -> CstInputValue {
    match v {
        Value::Null => CstInputValue::Null,
        Value::Bool(v) => CstInputValue::Bool(*v),
        Value::Number(v) => CstInputValue::Number(v.to_string()),
        Value::String(v) => CstInputValue::String(v.clone()),
        Value::Array(v) => CstInputValue::Array(v.iter().map(input).collect()),
        Value::Object(v) => {
            CstInputValue::Object(v.iter().map(|(k, v)| (k.clone(), input(v))).collect())
        }
    }
}

// Recursively patch changed fields, retaining comments and formatting on all other fields.
fn sync_object(object: CstObject, value: &Value) -> Result<()> {
    let old = object.to_serde_value().context("Invalid object")?;
    let values = value.as_object().context("Expected an object")?;
    for key in old.as_object().unwrap().keys() {
        if !values.contains_key(key) {
            object.get(key).unwrap().remove();
        }
    }
    for (key, new) in values {
        if old.get(key) == Some(new) {
            continue;
        }
        if let Some(prop) = object.get(key) {
            if let (Some(obj), true) = (prop.object_value(), new.is_object()) {
                sync_object(obj, new)?;
            } else {
                prop.set_value(input(new));
            }
        } else {
            object.append(key, input(new));
        }
    }
    Ok(())
}

fn section_array(root: &CstRootNode, section: &str) -> Result<CstArray> {
    let obj = root
        .object_value()
        .context("Config must be a JSON object")?;
    let owner = if section == "rules" {
        obj.object_value_or_create("routing")
            .context("routing must be an object")?
    } else {
        obj
    };
    owner
        .array_value_or_create(section)
        .context("Section must be an array")
}

fn identity(v: &Value) -> String {
    v.get("tag")
        .or_else(|| v.get("ruleTag"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{:x}", Sha256::digest(v.to_string())))
}

impl Document {
    pub fn load(path: &Path) -> Result<Self> {
        let path = path
            .canonicalize()
            .with_context(|| format!("Cannot open {}", path.display()))?;
        Self::from_text(path.clone(), fs::read_to_string(path)?)
    }

    pub fn from_text(path: PathBuf, text: String) -> Result<Self> {
        let value = parse(&text)?;
        ensure!(value.is_object(), "Config must be an object");
        let mut meta = Metadata::default();
        let mut found = false;
        for line in text.lines() {
            if let Some(data) = line.strip_prefix(META) {
                ensure!(!found, "Duplicate xray-tui metadata");
                meta = serde_json::from_str(data).context("Invalid xray-tui metadata")?;
                found = true;
            } else if line.starts_with("// @xray-tui:") {
                bail!("Unsupported metadata version");
            }
        }
        Ok(Self {
            path,
            read_cache: RefCell::new(ReadCache {
                text: text.clone(),
                value: Some(value),
                entries: HashMap::new(),
            }),
            original_cache: RefCell::new(None),
            text: text.clone(),
            original: text,
            meta,
        })
    }

    pub fn rendered(&self) -> Result<String> {
        let body: String = self
            .text
            .split_inclusive('\n')
            .filter(|l| !l.starts_with(META))
            .collect();
        if self.meta.disabled.is_empty()
            && self.meta.subscriptions.is_empty()
            && self.meta.health.is_none()
        {
            return Ok(body);
        }
        Ok(format!(
            "{META}{}\n{body}",
            serde_json::to_string(&self.meta)?
        ))
    }

    pub fn dirty(&self) -> bool {
        self.rendered().map(|s| s != self.original).unwrap_or(true)
    }
    pub fn value(&self) -> Result<Value> {
        let mut cache = self.read_cache.borrow_mut();
        if cache.text != self.text {
            *cache = ReadCache {
                text: self.text.clone(),
                ..ReadCache::default()
            };
        }
        if cache.value.is_none() {
            cache.value = Some(parse(&self.text)?);
        }
        Ok(cache.value.as_ref().unwrap().clone())
    }

    pub fn same_as_original(&self) -> bool {
        if self.text == self.original {
            return true;
        }
        let mut original = self.original_cache.borrow_mut();
        if original
            .as_ref()
            .is_none_or(|(text, _)| text != &self.original)
        {
            *original = Some((self.original.clone(), parse(&self.original).ok()));
        }
        self.value().ok() == original.as_ref().unwrap().1
    }

    pub fn entries(&self, section: &str) -> Result<Vec<Entry>> {
        let mut cache = self.read_cache.borrow_mut();
        if cache.text != self.text {
            *cache = ReadCache {
                text: self.text.clone(),
                ..ReadCache::default()
            };
        }
        if !cache.entries.contains_key(section) {
            let root = CstRootNode::parse(&self.text, &ParseOptions::default())?;
            let array = section_array(&root, section)?;
            let entries = array
                .elements()
                .iter()
                .enumerate()
                .map(|(i, n)| Entry {
                    value: n.to_serde_value().unwrap_or(Value::Null),
                    raw: n.to_string(),
                    active_index: Some(i),
                    disabled_index: None,
                })
                .collect();
            cache.entries.insert(section.to_owned(), entries);
        }
        let mut entries = cache.entries[section].clone();
        drop(cache);
        for (i, d) in self
            .meta
            .disabled
            .iter()
            .enumerate()
            .filter(|(_, d)| d.section == section)
        {
            entries.push(Entry {
                value: parse(&d.raw)?,
                raw: d.raw.clone(),
                active_index: None,
                disabled_index: Some(i),
            });
        }
        Ok(entries)
    }

    pub fn replace_text(&mut self, text: String) -> Result<()> {
        let updated = Self::from_text(self.path.clone(), text)?;
        self.text = updated.text;
        self.meta = updated.meta;
        Ok(())
    }

    pub fn set_section(&mut self, key: &str, raw: &str) -> Result<()> {
        let value = parse(raw)?;
        let root = CstRootNode::parse(&self.text, &ParseOptions::default())?;
        let object = root.object_value().context("Expected root object")?;
        if let Some(prop) = object.get(key) {
            if let (Some(obj), true) = (prop.object_value(), value.is_object()) {
                sync_object(obj, &value)?;
            } else {
                prop.set_value(input(&value));
            }
        } else {
            object.append(key, input(&value));
        }
        self.text = root.to_string();
        Ok(())
    }

    pub fn section_raw(&self, key: &str) -> Result<String> {
        let root = CstRootNode::parse(&self.text, &ParseOptions::default())?;
        Ok(root
            .object_value()
            .context("Expected object")?
            .get(key)
            .and_then(|p| p.value())
            .context("Missing section")?
            .to_string())
    }

    pub fn set_section_raw(&mut self, key: &str, raw: &str) -> Result<()> {
        parse(raw)?;
        let root = CstRootNode::parse(&self.text, &ParseOptions::default())?;
        let obj = root.object_value().context("Expected object")?;
        let marker = unique_marker(&self.text, raw);
        if let Some(prop) = obj.get(key) {
            prop.set_value(CstInputValue::String(marker.clone()));
        } else {
            obj.append(key, CstInputValue::String(marker.clone()));
        }
        self.text = root
            .to_string()
            .replacen(&serde_json::to_string(&marker)?, raw, 1);
        Ok(())
    }

    /// A raw editor owns the entire selected object, including newly written comments.
    /// Structured edits use `put` instead, preserving the previous field comments.
    pub fn put_raw(&mut self, section: &str, entry: Option<&Entry>, raw: &str) -> Result<()> {
        let mut checked = self.clone();
        checked.put(section, entry, raw)?;
        if let Some(i) = entry.and_then(|e| e.active_index) {
            let root = CstRootNode::parse(&self.text, &ParseOptions::default())?;
            let array = section_array(&root, section)?;
            let marker = unique_marker(&self.text, raw);
            array
                .elements()
                .get(i)
                .and_then(CstNode::as_object)
                .context("Expected object")?
                .replace_with(CstInputValue::String(marker.clone()))
                .context("Cannot replace entry")?;
            self.text = root
                .to_string()
                .replacen(&serde_json::to_string(&marker)?, raw, 1);
        } else {
            *self = checked;
        }
        Ok(())
    }

    pub fn put(&mut self, section: &str, entry: Option<&Entry>, raw: &str) -> Result<()> {
        let value = parse(raw)?;
        ensure!(value.is_object(), "Expected a JSON object");
        if section == "outbounds" || section == "inbounds" {
            let tag = value["tag"]
                .as_str()
                .filter(|t| !t.is_empty())
                .context("A non-empty tag is required")?;
            for e in self.entries(section)? {
                if entry.is_some_and(|old| {
                    old.active_index == e.active_index && old.disabled_index == e.disabled_index
                }) {
                    continue;
                }
                ensure!(
                    e.value["tag"].as_str() != Some(tag),
                    "Tag already exists: {tag}"
                );
            }
            if let Some(old) = entry
                && let Some(old_tag) = old.value["tag"].as_str()
                && old_tag != tag
                && old.active_index.is_some()
            {
                self.ensure_unreferenced(section, old_tag)?;
            }
        }
        if let Some(i) = entry.and_then(|e| e.disabled_index) {
            self.meta.disabled[i].raw = raw.to_owned();
            return Ok(());
        }
        let root = CstRootNode::parse(&self.text, &ParseOptions::default())?;
        let array = section_array(&root, section)?;
        if let Some(i) = entry.and_then(|e| e.active_index) {
            let node = array
                .elements()
                .get(i)
                .cloned()
                .context("Entry no longer exists")?;
            sync_object(node.as_object().context("Expected object")?, &value)?;
            self.text = root.to_string();
        } else {
            self.text = insert_raw(&root, &array, array.elements().len(), raw)?;
        }
        Ok(())
    }

    pub fn ensure_unreferenced(&self, section: &str, tag: &str) -> Result<()> {
        let v = self.value()?;
        fn referenced(v: &Value, tag: &str, section: &str) -> bool {
            match v {
                Value::Object(obj) => obj.iter().any(|(k, v)| {
                    let direct = if section == "outbounds" {
                        ["outboundTag", "dialerProxy", "detour", "tag"].contains(&k.as_str())
                    } else {
                        k == "inboundTag"
                    };
                    (direct
                        && (v.as_str() == Some(tag)
                            || v.as_array()
                                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(tag)))))
                        || (section == "outbounds"
                            && k == "selector"
                            && v.as_array().is_some_and(|a| {
                                a.iter()
                                    .any(|p| p.as_str().is_some_and(|p| tag.starts_with(p)))
                            }))
                        || referenced(v, tag, section)
                }),
                Value::Array(a) => a.iter().any(|v| referenced(v, tag, section)),
                _ => false,
            }
        }
        // Remove the defining tag itself; all references (including DNS/balancers/dialerProxy) remain.
        let mut check = v.clone();
        if let Some(a) = check[section].as_array_mut() {
            for e in a {
                if e["tag"].as_str() == Some(tag) {
                    e.as_object_mut().unwrap().remove("tag");
                }
            }
        }
        ensure!(
            !referenced(&check, tag, section),
            "'{tag}' is still referenced. Disable/edit its routes, DNS, balancer or proxy chain first."
        );
        Ok(())
    }

    pub fn toggle(&mut self, section: &str, entry: &Entry) -> Result<()> {
        let root = CstRootNode::parse(&self.text, &ParseOptions::default())?;
        let array = section_array(&root, section)?;
        if let Some(i) = entry.disabled_index {
            let d = &self.meta.disabled[i];
            if section != "rules" {
                ensure!(
                    !array.elements().iter().any(|n| n
                        .to_serde_value()
                        .is_some_and(|v| v["tag"] == entry.value["tag"])),
                    "Tag already exists"
                );
            }
            let elements = array.elements();
            let pos = d
                .successors
                .iter()
                .find_map(|key| {
                    elements
                        .iter()
                        .position(|n| n.to_serde_value().is_some_and(|v| identity(&v) == *key))
                })
                .unwrap_or(d.index.min(elements.len()));
            self.text = insert_raw(&root, &array, pos, &d.raw)?;
            self.meta.disabled.remove(i);
        } else if let Some(i) = entry.active_index {
            if section == "outbounds" {
                ensure!(
                    i != 0,
                    "The first outbound is the default. Choose another default with 'd' first."
                );
            }
            if section != "rules" {
                self.ensure_unreferenced(
                    section,
                    entry.value["tag"].as_str().context("Missing tag")?,
                )?;
            }
            let elements = array.elements();
            let node = elements.get(i).cloned().context("Missing entry")?;
            let mut removed_comments: Vec<_> =
                root.children().iter().flat_map(comment_strings).collect();
            let inner_comments = comment_strings(&node);
            let mut disabled = Disabled {
                section: section.into(),
                index: i,
                raw: node.to_string(),
                successors: elements
                    .iter()
                    .skip(i + 1)
                    .filter_map(CstNode::to_serde_value)
                    .map(|v| identity(&v))
                    .collect(),
            };
            node.remove();
            // CST removal also removes inline annotations around the object. Store those
            // with the paused entry so a toggle cannot silently discard user comments.
            for comment in root
                .children()
                .iter()
                .flat_map(comment_strings)
                .chain(inner_comments)
            {
                if let Some(i) = removed_comments.iter().position(|s| *s == comment) {
                    removed_comments.remove(i);
                }
            }
            if !removed_comments.is_empty() {
                disabled.raw = format!("{}\n{}", removed_comments.join("\n"), disabled.raw);
            }
            self.meta.disabled.push(disabled);
            self.text = root.to_string();
        }
        Ok(())
    }

    pub fn delete(&mut self, section: &str, entry: &Entry) -> Result<()> {
        if let Some(i) = entry.disabled_index {
            self.meta.disabled.remove(i);
            return Ok(());
        }
        let i = entry.active_index.context("Missing entry")?;
        if section == "outbounds" {
            ensure!(
                i != 0,
                "Choose a different default before deleting this outbound"
            );
        }
        if section != "rules" {
            self.ensure_unreferenced(section, entry.value["tag"].as_str().context("Missing tag")?)?;
        }
        let root = CstRootNode::parse(&self.text, &ParseOptions::default())?;
        section_array(&root, section)?
            .elements()
            .get(i)
            .cloned()
            .context("Missing entry")?
            .remove();
        self.text = root.to_string();
        Ok(())
    }

    pub fn move_entry(&mut self, section: &str, from: usize, to: usize) -> Result<()> {
        let root = CstRootNode::parse(&self.text, &ParseOptions::default())?;
        let array = section_array(&root, section)?;
        let elements = array.elements();
        ensure!(
            from < elements.len() && to < elements.len(),
            "Cannot move beyond list boundary"
        );
        let mut order: Vec<usize> = (0..elements.len()).collect();
        let moved = order.remove(from);
        order.insert(to, moved);
        // sort is stable: identical rules retain their relative order.
        let ordered: Vec<String> = order.iter().map(|i| elements[*i].to_string()).collect();
        array.sort_elements().by_key(|n| {
            ordered
                .iter()
                .position(|s| *s == n.to_string())
                .unwrap_or(usize::MAX)
        });
        self.text = root.to_string();
        Ok(())
    }

    pub fn validate_structure(&self) -> Result<()> {
        if let Some(settings) = &self.meta.health {
            settings.validate()?;
        }
        let v = self.value()?;
        for section in ["outbounds", "inbounds"] {
            let mut tags = HashSet::new();
            for e in v[section].as_array().into_iter().flatten() {
                if let Some(tag) = e["tag"].as_str() {
                    ensure!(tags.insert(tag), "Duplicate {section} tag: {tag}");
                }
            }
        }
        let mut tags: HashSet<_> = v["outbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e["tag"].as_str())
            .collect();
        // API and metrics handlers create their own outbound proxies inside Xray.
        for key in ["api", "metrics"] {
            if let Some(tag) = v[key]["tag"].as_str() {
                tags.insert(tag);
            }
        }
        if v["metrics"].get("listen").is_some() && v["metrics"].get("tag").is_none() {
            tags.insert("Metrics");
        }
        // Existing files may contain dormant/unresolved targets accepted by the core.
        // Preserve those, but prevent introducing new missing targets in this draft.
        let baseline = parse(&self.original)?;
        let baseline_tags: HashSet<_> = baseline["outbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e["tag"].as_str())
            .collect();
        let inherited_missing: HashSet<_> = baseline
            .pointer("/routing/rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|r| r["outboundTag"].as_str())
            .filter(|tag| !baseline_tags.contains(tag))
            .collect();
        for rule in v
            .pointer("/routing/rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(tag) = rule["outboundTag"].as_str() {
                ensure!(
                    tags.contains(tag) || inherited_missing.contains(tag),
                    "Route references missing outbound '{tag}'"
                );
            }
        }
        Ok(())
    }
}

fn insert_raw(root: &CstRootNode, array: &CstArray, index: usize, raw: &str) -> Result<String> {
    parse(raw)?;
    let marker = unique_marker(&root.to_string(), raw);
    array.insert(index, CstInputValue::String(marker.clone()));
    Ok(root
        .to_string()
        .replacen(&serde_json::to_string(&marker)?, raw, 1))
}

fn unique_marker(text: &str, raw: &str) -> String {
    let mut marker = "__xray_tui_insert__".to_string();
    while text.contains(&marker) || raw.contains(&marker) {
        marker.push('_');
    }
    marker
}

fn comment_strings(node: &CstNode) -> Vec<String> {
    match node {
        CstNode::Container(c) => c.children().iter().flat_map(comment_strings).collect(),
        _ if node.is_comment() => vec![node.to_string()],
        _ => vec![],
    }
}

pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let mut f =
        tempfile::NamedTempFile::new_in(path.parent().context("Missing parent directory")?)?;
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    f.write_all(data)?;
    f.as_file().sync_all()?;
    f.persist(path).map_err(|e| e.error)?;
    fs::File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

pub fn backup(path: &Path) -> Result<PathBuf> {
    let mut f = tempfile::Builder::new()
        .prefix(&format!(
            "{}.backup-",
            path.file_name().unwrap().to_string_lossy()
        ))
        .tempfile_in(path.parent().unwrap())?;
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    f.write_all(&fs::read(path)?)?;
    f.as_file().sync_all()?;
    let (_, path) = f.keep()?;
    Ok(path)
}

pub fn redacted(mut value: Value) -> Value {
    fn walk(v: &mut Value) {
        match v {
            Value::Object(o) => {
                for (k, v) in o {
                    if [
                        "id",
                        "password",
                        "privateKey",
                        "publicKey",
                        "shortId",
                        "shortIds",
                        "token",
                        "secret",
                        "url",
                    ]
                    .iter()
                    .any(|key| k.eq_ignore_ascii_case(key))
                    {
                        *v = Value::String("••••••••".into());
                    } else {
                        walk(v);
                    }
                }
            }
            Value::Array(a) => a.iter_mut().for_each(walk),
            _ => (),
        }
    }
    walk(&mut value);
    value
}
