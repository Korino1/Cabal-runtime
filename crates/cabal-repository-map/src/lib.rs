//! Deterministic, bounded repository facts for the Cabal Runtime hook path.
//!
//! The crate deliberately stores syntactic observations only. It does not
//! resolve types, infer a call graph, retrieve intent, or expose source text.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fmt, fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapOpenOptions},
};
use cargo_metadata::MetadataCommand;
use fs2::FileExt;
use ignore::WalkBuilder;
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn::{
    File, ImplItemFn, Item, ItemConst, ItemEnum, ItemImpl, ItemMacro, ItemMod, ItemStatic,
    ItemStruct, ItemTrait, ItemType, ItemUnion, ItemUse, Macro, TraitItemFn, TypePath, UseTree,
    spanned::Spanned,
    visit::{self, Visit},
};

pub const INDEX_SCHEMA: &str = "cabal.repository_map.v1";
pub const INVENTORY_SCHEMA: &str = "cabal.repository_inventory.v1";
pub const MAX_WALKED_FILES: usize = 100_000;
pub const MAX_INDEXED_FILE_BYTES: u64 = 1_048_576;
pub const MAX_PATH_BYTES: usize = 4_096;
pub const MAX_RUST_SYMBOLS_PER_FILE: usize = 2_048;
pub const MAX_RUST_REFERENCES_PER_FILE: usize = 2_048;
pub const MAX_IMPORTS_PER_FILE: usize = 2_048;
pub const MAX_INDEX_BYTES: usize = 134_217_728;
pub const MAX_INVENTORY_BYTES: usize = 65_536;
pub const MAX_INVENTORY_PATHS: usize = 256;
pub const MAX_INVENTORY_PACKAGES: usize = 128;
pub const MAX_INVENTORY_TARGETS: usize = 512;

const INDEX_FILE: &str = "index-v1.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepositoryMapIndex {
    pub schema: String,
    pub files: Vec<FileFact>,
    pub cargo: CargoFacts,
    pub omissions: OmissionCounts,
    pub completeness: Completeness,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OmissionCounts {
    pub walked_limit: u64,
    pub walk_errors: u64,
    pub symlinks: u64,
    pub invalid_paths: u64,
    pub path_too_long: u64,
    pub oversized_files: u64,
    pub malformed_rust: u64,
    pub index_limit: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Bounded,
    CargoUnavailable,
    BoundedAndCargoUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileFact {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub bytes: u64,
    pub language: LanguageClass,
    pub classification: FileClassification,
    pub rust: RustParseStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageClass {
    Rust,
    Toml,
    Text,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileClassification {
    Source,
    Test,
    Manifest,
    Configuration,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RustParseStatus {
    NotRust,
    Parsed { facts: RustFileFacts },
    Malformed,
    Oversized,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RustFileFacts {
    pub modules: Vec<ModuleFact>,
    pub definitions: Vec<DefinitionFact>,
    pub imports: Vec<ImportFact>,
    pub references: Vec<ReferenceFact>,
    pub reference_edges: Vec<String>,
    pub tests: Vec<TestFact>,
    pub omissions: RustOmissions,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RustOmissions {
    pub symbols: u64,
    pub imports: u64,
    pub references: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleFact {
    pub name: String,
    pub visibility: Visibility,
    pub line: u32,
    pub inline: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DefinitionFact {
    pub name: String,
    pub kind: DefinitionKind,
    pub visibility: Visibility,
    pub line: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionKind {
    Function,
    Struct,
    Enum,
    Trait,
    Type,
    Const,
    Static,
    Union,
    Macro,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Private,
    Public,
    Restricted { scope: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImportFact {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub glob: bool,
    pub line: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReferenceFact {
    pub path: String,
    pub line: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TestFact {
    pub name: String,
    pub line: u32,
    pub references: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CargoFacts {
    pub available: bool,
    pub packages: Vec<CargoPackage>,
    pub dependency_edges: Vec<CargoDependencyEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CargoPackage {
    pub name: String,
    pub version: String,
    pub targets: Vec<CargoTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CargoTarget {
    pub name: String,
    pub kinds: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CargoDependencyEdge {
    pub package: String,
    pub dependency: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RefreshResult {
    pub index: RepositoryMapIndex,
    pub reused_files: u64,
    pub reparsed_files: u64,
    pub deleted_files: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepositoryInventory {
    pub schema: String,
    pub indexed_files: u64,
    pub projected_files: u64,
    pub omitted_files: u64,
    pub source_paths: Vec<String>,
    pub test_paths: Vec<String>,
    pub manifest_paths: Vec<String>,
    pub configuration_paths: Vec<String>,
    pub packages: Vec<InventoryPackage>,
    pub indexed_packages: u64,
    pub omitted_packages: u64,
    pub indexed_targets: u64,
    pub omitted_targets: u64,
    pub projection_complete: bool,
    pub completeness: Completeness,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InventoryPackage {
    pub name: String,
    pub version: String,
    pub targets: Vec<CargoTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolMatch {
    pub file: String,
    pub definition: DefinitionFact,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportMatch {
    pub file: String,
    pub import: ImportFact,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceMatch {
    pub file: String,
    pub reference: ReferenceFact,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestMatch {
    pub file: String,
    pub test: TestFact,
}

#[derive(Debug)]
pub enum RepositoryMapError {
    Io(io::Error),
    Json(serde_json::Error),
    NoGitServiceDirectory,
    StateRootOutsideGitService,
    InvalidWorkspace,
    IndexTooLarge,
    FileChangedDuringRefresh,
    InvalidPrivateRequest,
}

impl fmt::Display for RepositoryMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "repository map I/O: {error}"),
            Self::Json(error) => write!(f, "repository map JSON: {error}"),
            Self::NoGitServiceDirectory => write!(f, "workspace has no Git service directory"),
            Self::StateRootOutsideGitService => {
                write!(f, "state root is not inside the Git service directory")
            }
            Self::InvalidWorkspace => write!(f, "workspace is not a directory"),
            Self::IndexTooLarge => {
                write!(f, "bounded repository index cannot fit in the index limit")
            }
            Self::FileChangedDuringRefresh => write!(f, "file changed during repository refresh"),
            Self::InvalidPrivateRequest => write!(f, "private repository request is invalid"),
        }
    }
}

impl std::error::Error for RepositoryMapError {}
impl From<io::Error> for RepositoryMapError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for RepositoryMapError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// Refresh the private index. `state_root` must be under the workspace Git service directory.
pub fn refresh(workspace: &Path, state_root: &Path) -> Result<RefreshResult, RepositoryMapError> {
    let workspace =
        fs::canonicalize(workspace).map_err(|_| RepositoryMapError::InvalidWorkspace)?;
    if !workspace.is_dir() {
        return Err(RepositoryMapError::InvalidWorkspace);
    }
    let git_dir = git_service_dir(&workspace).ok_or(RepositoryMapError::NoGitServiceDirectory)?;
    let (state_root, state_dir) = prepare_state_root(&git_dir, state_root)?;
    let mut lock_options = CapOpenOptions::new();
    lock_options.create(true).read(true).write(true);
    let refresh_lock = state_dir
        .open_with("refresh.lock", &lock_options)?
        .into_std();
    FileExt::lock_exclusive(&refresh_lock)?;

    let previous = load_from_dir(&state_dir)?;
    let prior = previous
        .as_ref()
        .map(|index| {
            index
                .files
                .iter()
                .map(|file| (file.path.clone(), file))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let mut files = Vec::new();
    let mut omissions = OmissionCounts::default();
    let mut reused_files = 0;
    let mut reparsed_files = 0;
    let mut candidates = BTreeMap::new();

    let mut builder = WalkBuilder::new(&workspace);
    builder
        .standard_filters(true)
        .follow_links(false)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .filter_entry(|entry| {
            entry.depth() == 0
                || !entry
                    .file_name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(".git")
        });
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(_) => {
                omissions.walk_errors += 1;
                continue;
            }
        };
        if entry.path() == workspace {
            continue;
        }
        if entry.path().starts_with(&state_root) {
            continue;
        }
        let file_type = match entry.file_type() {
            Some(value) => value,
            None => {
                omissions.invalid_paths += 1;
                continue;
            }
        };
        if file_type.is_symlink() {
            omissions.symlinks += 1;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let path = match normalized_relative(entry.path(), &workspace) {
            Some(path) if path.len() <= MAX_PATH_BYTES => path,
            Some(_) => {
                omissions.path_too_long += 1;
                continue;
            }
            None => {
                omissions.invalid_paths += 1;
                continue;
            }
        };
        if candidates.len() >= MAX_WALKED_FILES {
            let largest = candidates
                .last_key_value()
                .expect("candidate map is non-empty at its limit")
                .0;
            if path >= *largest {
                omissions.walked_limit += 1;
                continue;
            }
            candidates.pop_last();
            omissions.walked_limit += 1;
        }
        candidates.insert(path, entry.path().to_path_buf());
    }
    for (path, disk_path) in &candidates {
        let bytes = fs::metadata(disk_path)?.len();
        if bytes > MAX_INDEXED_FILE_BYTES {
            omissions.oversized_files += 1;
            if let Some(old) = prior.get(path)
                && old.sha256.is_none()
                && old.bytes == bytes
            {
                files.push((*old).clone());
                reused_files += 1;
            } else {
                files.push(oversized_file(path.clone(), bytes));
                reparsed_files += 1;
            }
            continue;
        }
        let raw = read_bounded_file(disk_path)?;
        let bytes = raw.len() as u64;
        let sha256 = format!("{:x}", Sha256::digest(&raw));
        if let Some(old) = prior.get(path)
            && old.sha256.as_deref() == Some(&sha256)
            && old.bytes == bytes
        {
            files.push((*old).clone());
            reused_files += 1;
            continue;
        }
        let file = parse_file(path.clone(), sha256, bytes, &raw, &mut omissions);
        files.push(file);
        reparsed_files += 1;
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let deleted_files = prior
        .keys()
        .filter(|path| !candidates.contains_key(*path))
        .count() as u64;
    let cargo_changed = previous
        .as_ref()
        .is_none_or(|old| !old.cargo.available || cargo_inputs_changed(old, &files));
    let cargo_inputs_bounded = files
        .iter()
        .filter(|file| is_cargo_input(file))
        .all(|file| file.sha256.is_some());
    let cargo = if !cargo_inputs_bounded {
        CargoFacts::default()
    } else if cargo_changed {
        collect_cargo_facts(&workspace)
    } else {
        previous
            .as_ref()
            .expect("previous exists when Cargo data is reused")
            .cargo
            .clone()
    };
    let mut index = RepositoryMapIndex {
        schema: INDEX_SCHEMA.to_owned(),
        files,
        cargo,
        omissions,
        completeness: Completeness::Complete,
    };
    finalize_completeness(&mut index);
    enforce_index_bound(&mut index)?;
    persist(&state_dir, &index)?;
    FileExt::unlock(&refresh_lock)?;
    Ok(RefreshResult {
        index,
        reused_files,
        reparsed_files,
        deleted_files,
    })
}

/// Load only a complete, compatible persisted index. Corrupt or old state is ignored.
pub fn load(state_root: &Path) -> Result<Option<RepositoryMapIndex>, RepositoryMapError> {
    let path = state_root.join(INDEX_FILE);
    match fs::metadata(&path) {
        Ok(metadata) if metadata.len() > MAX_INDEX_BYTES as u64 => return Ok(None),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    decode_index(&raw)
}

fn load_from_dir(state_dir: &Dir) -> Result<Option<RepositoryMapIndex>, RepositoryMapError> {
    match state_dir.metadata(INDEX_FILE) {
        Ok(metadata) if metadata.len() > MAX_INDEX_BYTES as u64 => return Ok(None),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    decode_index(&state_dir.read(INDEX_FILE)?)
}

fn decode_index(raw: &[u8]) -> Result<Option<RepositoryMapIndex>, RepositoryMapError> {
    let index: RepositoryMapIndex = match serde_json::from_slice(raw) {
        Ok(index) => index,
        Err(_) => return Ok(None),
    };
    if index.schema != INDEX_SCHEMA || !index_is_valid(&index) {
        return Ok(None);
    }
    Ok(Some(index))
}

/// Alias for consumers that treat the persisted index as the current snapshot.
pub fn current(state_root: &Path) -> Result<Option<RepositoryMapIndex>, RepositoryMapError> {
    load(state_root)
}

/// Load the current snapshot through a Git-directory capability without
/// following a concurrently replaced state path outside the repository.
pub fn current_for(
    workspace: &Path,
    state_root: &Path,
) -> Result<Option<RepositoryMapIndex>, RepositoryMapError> {
    let Some(state_dir) = open_existing_state_dir(workspace, state_root)? else {
        return Ok(None);
    };
    load_from_dir(&state_dir)
}

/// Write a bounded opaque hook request through the private state capability.
pub fn write_private_request(
    workspace: &Path,
    state_root: &Path,
    request_id: &str,
    raw: &[u8],
) -> Result<(), RepositoryMapError> {
    validate_request_id(request_id)?;
    let state_dir = open_existing_state_dir(workspace, state_root)?
        .ok_or(RepositoryMapError::StateRootOutsideGitService)?;
    state_dir.create_dir_all("requests")?;
    let requests = state_dir.open_dir("requests")?;
    let mut options = CapOpenOptions::new();
    options.create_new(true).write(true);
    let mut file = requests.open_with(request_id, &options)?;
    file.write_all(raw)?;
    Ok(())
}

/// Read and remove a bounded opaque hook request through the same capability.
pub fn read_private_request(
    workspace: &Path,
    state_root: &Path,
    request_id: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, RepositoryMapError> {
    validate_request_id(request_id)?;
    let state_dir = open_existing_state_dir(workspace, state_root)?
        .ok_or(RepositoryMapError::StateRootOutsideGitService)?;
    let requests = state_dir.open_dir("requests")?;
    let metadata = requests.metadata(request_id)?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(RepositoryMapError::InvalidPrivateRequest);
    }
    let mut raw = Vec::new();
    requests
        .open(request_id)?
        .take(max_bytes + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > max_bytes {
        return Err(RepositoryMapError::InvalidPrivateRequest);
    }
    requests.remove_file(request_id)?;
    Ok(raw)
}

pub fn inventory(index: &RepositoryMapIndex) -> RepositoryInventory {
    let indexed_packages = index.cargo.packages.len() as u64;
    let indexed_targets = index
        .cargo
        .packages
        .iter()
        .map(|package| package.targets.len() as u64)
        .sum();
    let mut result = RepositoryInventory {
        schema: INVENTORY_SCHEMA.to_owned(),
        indexed_files: index.files.len() as u64,
        projected_files: 0,
        omitted_files: 0,
        source_paths: Vec::new(),
        test_paths: Vec::new(),
        manifest_paths: Vec::new(),
        configuration_paths: Vec::new(),
        packages: index
            .cargo
            .packages
            .iter()
            .take(MAX_INVENTORY_PACKAGES)
            .map(|package| InventoryPackage {
                name: package.name.clone(),
                version: package.version.clone(),
                targets: package
                    .targets
                    .iter()
                    .take(MAX_INVENTORY_TARGETS)
                    .cloned()
                    .collect(),
            })
            .collect(),
        indexed_packages,
        omitted_packages: 0,
        indexed_targets,
        omitted_targets: 0,
        projection_complete: true,
        completeness: index.completeness.clone(),
    };
    for file in &index.files {
        if total_inventory_paths(&result) >= MAX_INVENTORY_PATHS {
            continue;
        }
        match file.classification {
            FileClassification::Source => result.source_paths.push(file.path.clone()),
            FileClassification::Test => result.test_paths.push(file.path.clone()),
            FileClassification::Manifest => result.manifest_paths.push(file.path.clone()),
            FileClassification::Configuration => result.configuration_paths.push(file.path.clone()),
            FileClassification::Other => {}
        }
    }
    bound_inventory(&mut result);
    update_inventory_counts(&mut result, omitted_file_count(&index.omissions));
    bound_inventory(&mut result);
    update_inventory_counts(&mut result, omitted_file_count(&index.omissions));
    result
}

/// Projection compatible with default `rg --files` hidden-path behavior.
pub fn visible_inventory(index: &RepositoryMapIndex) -> RepositoryInventory {
    let mut result = inventory(index);
    result.source_paths.retain(|path| !is_hidden_path(path));
    result.test_paths.retain(|path| !is_hidden_path(path));
    result.manifest_paths.retain(|path| !is_hidden_path(path));
    result
        .configuration_paths
        .retain(|path| !is_hidden_path(path));
    update_inventory_counts(&mut result, omitted_file_count(&index.omissions));
    bound_inventory(&mut result);
    update_inventory_counts(&mut result, omitted_file_count(&index.omissions));
    result
}

/// Conservative UTF-8 byte estimate for the default `rg --files` list.
pub fn estimated_visible_file_list_bytes(index: &RepositoryMapIndex) -> usize {
    index
        .files
        .iter()
        .filter(|file| !is_hidden_path(&file.path))
        .map(|file| file.path.len().saturating_add(1))
        .sum()
}

pub fn inventory_from_state(
    state_root: &Path,
) -> Result<Option<RepositoryInventory>, RepositoryMapError> {
    Ok(load(state_root)?.as_ref().map(inventory))
}
pub fn inventory_bytes(inventory: &RepositoryInventory) -> Vec<u8> {
    serde_json::to_vec(inventory).expect("inventory is serializable")
}

pub fn find_symbols(index: &RepositoryMapIndex, name: &str) -> Vec<SymbolMatch> {
    index
        .files
        .iter()
        .filter_map(|file| parsed(&file.rust).map(|facts| (file, facts)))
        .flat_map(|(file, facts)| {
            facts
                .definitions
                .iter()
                .filter(move |definition| definition.name == name)
                .map(move |definition| SymbolMatch {
                    file: file.path.clone(),
                    definition: definition.clone(),
                })
        })
        .collect()
}
pub fn find_imports(index: &RepositoryMapIndex, path: &str) -> Vec<ImportMatch> {
    index
        .files
        .iter()
        .filter_map(|file| parsed(&file.rust).map(|facts| (file, facts)))
        .flat_map(|(file, facts)| {
            facts
                .imports
                .iter()
                .filter(move |import| import.path == path)
                .map(move |import| ImportMatch {
                    file: file.path.clone(),
                    import: import.clone(),
                })
        })
        .collect()
}
pub fn find_references(index: &RepositoryMapIndex, path: &str) -> Vec<ReferenceMatch> {
    index
        .files
        .iter()
        .filter_map(|file| parsed(&file.rust).map(|facts| (file, facts)))
        .flat_map(|(file, facts)| {
            facts
                .references
                .iter()
                .filter(move |reference| reference.path == path)
                .map(move |reference| ReferenceMatch {
                    file: file.path.clone(),
                    reference: reference.clone(),
                })
        })
        .collect()
}
pub fn find_tests(index: &RepositoryMapIndex, name: &str) -> Vec<TestMatch> {
    index
        .files
        .iter()
        .filter_map(|file| parsed(&file.rust).map(|facts| (file, facts)))
        .flat_map(|(file, facts)| {
            facts
                .tests
                .iter()
                .filter(move |test| test.name == name)
                .map(move |test| TestMatch {
                    file: file.path.clone(),
                    test: test.clone(),
                })
        })
        .collect()
}

pub fn find_associated_tests(index: &RepositoryMapIndex, symbol: &str) -> Vec<TestMatch> {
    index
        .files
        .iter()
        .filter_map(|file| parsed(&file.rust).map(|facts| (file, facts)))
        .flat_map(|(file, facts)| {
            facts
                .tests
                .iter()
                .filter(move |test| {
                    let symbol_name = symbol.rsplit("::").next().unwrap_or(symbol);
                    test.references.iter().any(|reference| {
                        reference == symbol
                            || reference
                                .rsplit("::")
                                .next()
                                .is_some_and(|name| name == symbol_name)
                    })
                })
                .map(move |test| TestMatch {
                    file: file.path.clone(),
                    test: test.clone(),
                })
        })
        .collect()
}

fn parsed(status: &RustParseStatus) -> Option<&RustFileFacts> {
    match status {
        RustParseStatus::Parsed { facts } => Some(facts),
        _ => None,
    }
}

fn git_service_dir(workspace: &Path) -> Option<PathBuf> {
    let dot_git = workspace.join(".git");
    if dot_git.is_dir() {
        return fs::canonicalize(dot_git).ok();
    }
    let content = fs::read_to_string(dot_git).ok()?;
    let path = content.trim().strip_prefix("gitdir: ")?;
    let path = PathBuf::from(path);
    fs::canonicalize(if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    })
    .ok()
}

fn prepare_state_root(git_dir: &Path, path: &Path) -> Result<(PathBuf, Dir), RepositoryMapError> {
    let git_dir = fs::canonicalize(git_dir)?;
    let relative = relative_state_path(&git_dir, path)?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RepositoryMapError::StateRootOutsideGitService);
    }
    let git_cap = Dir::open_ambient_dir(&git_dir, ambient_authority())?;
    git_cap.create_dir_all(&relative)?;
    let state_dir = git_cap.open_dir(&relative)?;
    let canonical = fs::canonicalize(git_dir.join(&relative))?;
    if !canonical.starts_with(&git_dir) {
        return Err(RepositoryMapError::StateRootOutsideGitService);
    }
    Ok((canonical, state_dir))
}

fn relative_state_path(git_dir: &Path, path: &Path) -> Result<PathBuf, RepositoryMapError> {
    if let Ok(relative) = path.strip_prefix(git_dir) {
        return Ok(relative.to_path_buf());
    }
    let mut missing = Vec::<OsString>::new();
    let mut ancestor = path;
    while !ancestor.exists() {
        missing.push(
            ancestor
                .file_name()
                .ok_or(RepositoryMapError::StateRootOutsideGitService)?
                .to_owned(),
        );
        ancestor = ancestor
            .parent()
            .ok_or(RepositoryMapError::StateRootOutsideGitService)?;
    }
    let canonical_ancestor = fs::canonicalize(ancestor)?;
    let mut relative = canonical_ancestor
        .strip_prefix(git_dir)
        .map_err(|_| RepositoryMapError::StateRootOutsideGitService)?
        .to_path_buf();
    for component in missing.iter().rev() {
        relative.push(component);
    }
    Ok(relative)
}

fn open_existing_state_dir(
    workspace: &Path,
    state_root: &Path,
) -> Result<Option<Dir>, RepositoryMapError> {
    let workspace =
        fs::canonicalize(workspace).map_err(|_| RepositoryMapError::InvalidWorkspace)?;
    let git_dir = git_service_dir(&workspace).ok_or(RepositoryMapError::NoGitServiceDirectory)?;
    let relative = relative_state_path(&git_dir, state_root)?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RepositoryMapError::StateRootOutsideGitService);
    }
    let git_cap = Dir::open_ambient_dir(&git_dir, ambient_authority())?;
    match git_cap.open_dir(relative) {
        Ok(state_dir) => Ok(Some(state_dir)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn validate_request_id(request_id: &str) -> Result<(), RepositoryMapError> {
    if request_id.len() == 69
        && request_id.ends_with(".json")
        && request_id[..64]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(RepositoryMapError::InvalidPrivateRequest)
    }
}

fn normalized_relative(path: &Path, workspace: &Path) -> Option<String> {
    let relative = path.strip_prefix(workspace).ok()?;
    if relative.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return None;
    }
    Some(relative.to_str()?.replace('\\', "/"))
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, RepositoryMapError> {
    let mut raw = Vec::new();
    fs::File::open(path)?
        .take(MAX_INDEXED_FILE_BYTES + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_INDEXED_FILE_BYTES {
        return Err(RepositoryMapError::FileChangedDuringRefresh);
    }
    Ok(raw)
}

fn parse_file(
    relative: String,
    sha256: String,
    bytes: u64,
    raw: &[u8],
    omissions: &mut OmissionCounts,
) -> FileFact {
    let language = language_for(&relative);
    let classification = classify_path(&relative);
    let rust = if language != LanguageClass::Rust {
        RustParseStatus::NotRust
    } else if bytes > MAX_INDEXED_FILE_BYTES {
        omissions.oversized_files += 1;
        RustParseStatus::Oversized
    } else {
        match std::str::from_utf8(raw)
            .ok()
            .and_then(|source| syn::parse_file(source).ok())
        {
            Some(file) => RustParseStatus::Parsed {
                facts: extract_rust_facts(&file),
            },
            None => {
                omissions.malformed_rust += 1;
                RustParseStatus::Malformed
            }
        }
    };
    FileFact {
        path: relative,
        sha256: Some(sha256),
        bytes,
        language,
        classification,
        rust,
    }
}

fn oversized_file(path: String, bytes: u64) -> FileFact {
    let language = language_for(&path);
    FileFact {
        classification: classify_path(&path),
        path,
        sha256: None,
        bytes,
        language,
        rust: if language == LanguageClass::Rust {
            RustParseStatus::Oversized
        } else {
            RustParseStatus::NotRust
        },
    }
}

fn language_for(path: &str) -> LanguageClass {
    if path.ends_with(".rs") {
        LanguageClass::Rust
    } else if path.ends_with(".toml") {
        LanguageClass::Toml
    } else if path.ends_with(".md") || path.ends_with(".txt") || path.ends_with(".rst") {
        LanguageClass::Text
    } else {
        LanguageClass::Other
    }
}
fn classify_path(path: &str) -> FileClassification {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.eq_ignore_ascii_case("cargo.toml") {
        FileClassification::Manifest
    } else if path.starts_with("tests/") || path.contains("/tests/") || name.ends_with("_test.rs") {
        FileClassification::Test
    } else if matches!(
        name,
        "Cargo.lock"
            | ".gitignore"
            | ".cargo/config.toml"
            | "rust-toolchain"
            | "rust-toolchain.toml"
    ) {
        FileClassification::Configuration
    } else if path.ends_with(".rs") {
        FileClassification::Source
    } else {
        FileClassification::Other
    }
}

fn extract_rust_facts(file: &File) -> RustFileFacts {
    let mut visitor = RustFactVisitor::default();
    visitor.visit_file(file);
    visitor.finish()
}

#[derive(Default)]
struct RustFactVisitor {
    modules: Vec<ModuleFact>,
    definitions: Vec<DefinitionFact>,
    imports: Vec<ImportFact>,
    references: Vec<ReferenceFact>,
    tests: Vec<TestFact>,
    owner_stack: Vec<String>,
    active_test: Option<usize>,
    omitted: RustOmissions,
}
impl RustFactVisitor {
    fn definition(
        &mut self,
        name: &str,
        kind: DefinitionKind,
        visibility: &syn::Visibility,
        span: proc_macro2::Span,
    ) {
        self.push_symbol(DefinitionFact {
            name: name.to_owned(),
            kind,
            visibility: visibility_for(visibility),
            line: span.start().line as u32,
        });
    }
    fn push_symbol(&mut self, fact: DefinitionFact) {
        if self.definitions.len() < MAX_RUST_SYMBOLS_PER_FILE {
            self.definitions.push(fact);
        } else {
            self.omitted.symbols += 1;
        }
    }
    fn reference(&mut self, path: &syn::Path, span: proc_macro2::Span) {
        let path = syn_path(path);
        if path.is_empty() {
            return;
        }
        if self.references.len() < MAX_RUST_REFERENCES_PER_FILE {
            self.references.push(ReferenceFact {
                path: path.clone(),
                line: span.start().line as u32,
            });
            if let Some(index) = self.active_test {
                self.tests[index].references.push(path);
            }
        } else {
            self.omitted.references += 1;
        }
    }
    fn finish(mut self) -> RustFileFacts {
        self.modules.sort_by(module_key);
        self.definitions.sort_by(definition_key);
        self.imports.sort_by(import_key);
        self.references.sort_by(reference_key);
        self.tests.sort_by(test_key);
        for test in &mut self.tests {
            test.references.sort();
            test.references.dedup();
        }
        self.modules.dedup();
        self.definitions.dedup();
        self.imports.dedup();
        self.references.dedup();
        self.tests.dedup();
        let reference_edges = self
            .references
            .iter()
            .map(|reference| reference.path.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        RustFileFacts {
            modules: self.modules,
            definitions: self.definitions,
            imports: self.imports,
            references: self.references,
            reference_edges,
            tests: self.tests,
            omissions: self.omitted,
        }
    }
}
impl<'ast> Visit<'ast> for RustFactVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        match item {
            Item::Struct(ItemStruct { ident, vis, .. }) => self.definition(
                &ident.to_string(),
                DefinitionKind::Struct,
                vis,
                ident.span(),
            ),
            Item::Enum(ItemEnum { ident, vis, .. }) => {
                self.definition(&ident.to_string(), DefinitionKind::Enum, vis, ident.span())
            }
            Item::Trait(ItemTrait { ident, vis, .. }) => {
                self.definition(&ident.to_string(), DefinitionKind::Trait, vis, ident.span())
            }
            Item::Type(ItemType { ident, vis, .. }) => {
                self.definition(&ident.to_string(), DefinitionKind::Type, vis, ident.span())
            }
            Item::Const(ItemConst { ident, vis, .. }) => {
                self.definition(&ident.to_string(), DefinitionKind::Const, vis, ident.span())
            }
            Item::Static(ItemStatic { ident, vis, .. }) => self.definition(
                &ident.to_string(),
                DefinitionKind::Static,
                vis,
                ident.span(),
            ),
            Item::Union(ItemUnion { ident, vis, .. }) => {
                self.definition(&ident.to_string(), DefinitionKind::Union, vis, ident.span())
            }
            Item::Macro(ItemMacro {
                ident: Some(ident), ..
            }) => self.definition(
                &ident.to_string(),
                DefinitionKind::Macro,
                &syn::Visibility::Inherited,
                ident.span(),
            ),
            Item::Mod(ItemMod {
                ident,
                vis,
                content,
                ..
            }) => self.modules.push(ModuleFact {
                name: ident.to_string(),
                visibility: visibility_for(vis),
                line: ident.span().start().line as u32,
                inline: content.is_some(),
            }),
            Item::Use(ItemUse { tree, .. }) => self.collect_use(tree, String::new(), 0),
            _ => {}
        }
        visit::visit_item(self, item);
    }
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let name = qualified_name(&self.owner_stack, &node.sig.ident.to_string());
        self.definition(
            &name,
            DefinitionKind::Function,
            &node.vis,
            node.sig.ident.span(),
        );
        let previous = self.active_test;
        if is_test(&node.attrs) {
            self.tests.push(TestFact {
                name,
                line: node.sig.ident.span().start().line as u32,
                references: Vec::new(),
            });
            self.active_test = Some(self.tests.len() - 1);
        }
        visit::visit_item_fn(self, node);
        self.active_test = previous;
    }
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        self.owner_stack.push(impl_owner(node));
        visit::visit_item_impl(self, node);
        self.owner_stack.pop();
    }
    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let name = qualified_name(&self.owner_stack, &node.sig.ident.to_string());
        self.definition(
            &name,
            DefinitionKind::Function,
            &node.vis,
            node.sig.ident.span(),
        );
        visit::visit_impl_item_fn(self, node);
    }
    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        self.owner_stack.push(node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.owner_stack.pop();
    }
    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        let name = qualified_name(&self.owner_stack, &node.sig.ident.to_string());
        self.definition(
            &name,
            DefinitionKind::Function,
            &syn::Visibility::Inherited,
            node.sig.ident.span(),
        );
        visit::visit_trait_item_fn(self, node);
    }
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        self.reference(&node.path, node.span());
        visit::visit_expr_path(self, node);
    }
    fn visit_type_path(&mut self, node: &'ast TypePath) {
        self.reference(&node.path, node.span());
        visit::visit_type_path(self, node);
    }
    fn visit_pat(&mut self, node: &'ast syn::Pat) {
        if let syn::Pat::Path(path) = node {
            self.reference(&path.path, path.span());
        }
        visit::visit_pat(self, node);
    }
    fn visit_macro(&mut self, node: &'ast Macro) {
        self.reference(&node.path, node.span());
        visit::visit_macro(self, node);
    }
}
impl RustFactVisitor {
    fn collect_use(&mut self, tree: &UseTree, prefix: String, line: u32) {
        match tree {
            UseTree::Path(path) => {
                let next = join_path(&prefix, &path.ident.to_string());
                self.collect_use(&path.tree, next, path.ident.span().start().line as u32);
            }
            UseTree::Name(name) => self.import(
                join_path(&prefix, &name.ident.to_string()),
                None,
                false,
                line.max(name.ident.span().start().line as u32),
            ),
            UseTree::Rename(rename) => self.import(
                join_path(&prefix, &rename.ident.to_string()),
                Some(rename.rename.to_string()),
                false,
                line.max(rename.ident.span().start().line as u32),
            ),
            UseTree::Glob(_) => self.import(prefix, None, true, line),
            UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_use(item, prefix.clone(), line);
                }
            }
        }
    }
    fn import(&mut self, path: String, alias: Option<String>, glob: bool, line: u32) {
        if self.imports.len() < MAX_IMPORTS_PER_FILE {
            self.imports.push(ImportFact {
                path,
                alias,
                glob,
                line,
            });
        } else {
            self.omitted.imports += 1;
        }
    }
}

fn visibility_for(value: &syn::Visibility) -> Visibility {
    match value {
        syn::Visibility::Inherited => Visibility::Private,
        syn::Visibility::Public(_) => Visibility::Public,
        syn::Visibility::Restricted(restricted) => Visibility::Restricted {
            scope: syn_path(&restricted.path),
        },
    }
}
fn syn_path(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}
fn join_path(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}::{name}")
    }
}
fn qualified_name(owners: &[String], name: &str) -> String {
    owners
        .last()
        .map_or_else(|| name.to_owned(), |owner| format!("{owner}::{name}"))
}
fn impl_owner(item: &ItemImpl) -> String {
    if let syn::Type::Path(path) = item.self_ty.as_ref() {
        let owner = syn_path(&path.path);
        if !owner.is_empty() {
            return owner;
        }
    }
    "<impl>".to_owned()
}
fn is_test(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("test")
            || (attribute.path().is_ident("cfg")
                && attribute
                    .meta
                    .to_token_stream()
                    .to_string()
                    .contains("test"))
    })
}
fn module_key(left: &ModuleFact, right: &ModuleFact) -> std::cmp::Ordering {
    (&left.name, left.line, left.inline).cmp(&(&right.name, right.line, right.inline))
}
fn definition_key(left: &DefinitionFact, right: &DefinitionFact) -> std::cmp::Ordering {
    (&left.name, left.kind, left.line).cmp(&(&right.name, right.kind, right.line))
}
fn import_key(left: &ImportFact, right: &ImportFact) -> std::cmp::Ordering {
    (&left.path, &left.alias, left.glob, left.line).cmp(&(
        &right.path,
        &right.alias,
        right.glob,
        right.line,
    ))
}
fn reference_key(left: &ReferenceFact, right: &ReferenceFact) -> std::cmp::Ordering {
    (&left.path, left.line).cmp(&(&right.path, right.line))
}
fn test_key(left: &TestFact, right: &TestFact) -> std::cmp::Ordering {
    (&left.name, left.line).cmp(&(&right.name, right.line))
}

fn collect_cargo_facts(workspace: &Path) -> CargoFacts {
    let metadata = match MetadataCommand::new()
        .current_dir(workspace)
        .no_deps()
        .other_options(["--locked".to_owned()])
        .exec()
    {
        Ok(metadata) => metadata,
        Err(_) => return CargoFacts::default(),
    };
    let member_ids = metadata.workspace_members.iter().collect::<BTreeSet<_>>();
    let mut packages = Vec::new();
    let mut dependency_edges = Vec::new();
    for package in metadata
        .packages
        .iter()
        .filter(|package| member_ids.contains(&package.id))
    {
        let package_key = format!("{}@{}", package.name, package.version);
        let mut targets = package
            .targets
            .iter()
            .map(|target| {
                let mut kinds = target
                    .kind
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                kinds.sort();
                CargoTarget {
                    name: target.name.clone(),
                    kinds,
                }
            })
            .collect::<Vec<_>>();
        targets.sort_by(|left, right| (&left.name, &left.kinds).cmp(&(&right.name, &right.kinds)));
        for dependency in &package.dependencies {
            dependency_edges.push(CargoDependencyEdge {
                package: package_key.clone(),
                dependency: dependency.name.clone(),
            });
        }
        packages.push(CargoPackage {
            name: package.name.clone(),
            version: package.version.to_string(),
            targets,
        });
    }
    packages.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    dependency_edges.sort();
    dependency_edges.dedup();
    CargoFacts {
        available: true,
        packages,
        dependency_edges,
    }
}

fn cargo_inputs_changed(old: &RepositoryMapIndex, current: &[FileFact]) -> bool {
    let old = old
        .files
        .iter()
        .filter(|file| is_cargo_input(file))
        .map(|file| (&file.path, &file.sha256))
        .collect::<BTreeMap<_, _>>();
    let current = current
        .iter()
        .filter(|file| is_cargo_input(file))
        .map(|file| (&file.path, &file.sha256))
        .collect::<BTreeMap<_, _>>();
    old != current
}
fn is_cargo_input(file: &FileFact) -> bool {
    file.path
        .rsplit('/')
        .next()
        .is_some_and(|name| name == "Cargo.toml" || name == "Cargo.lock")
}
fn finalize_completeness(index: &mut RepositoryMapIndex) {
    let bounded = has_omissions(&index.omissions);
    index.completeness = match (bounded, index.cargo.available) {
        (false, true) => Completeness::Complete,
        (true, true) => Completeness::Bounded,
        (false, false) => Completeness::CargoUnavailable,
        (true, false) => Completeness::BoundedAndCargoUnavailable,
    };
}
fn omitted_file_count(omissions: &OmissionCounts) -> u64 {
    omissions.walked_limit
        + omissions.walk_errors
        + omissions.symlinks
        + omissions.invalid_paths
        + omissions.path_too_long
        + omissions.index_limit
}
fn has_omissions(omissions: &OmissionCounts) -> bool {
    omitted_file_count(omissions) > 0
        || omissions.oversized_files > 0
        || omissions.malformed_rust > 0
}
fn enforce_index_bound(index: &mut RepositoryMapIndex) -> Result<(), RepositoryMapError> {
    if serde_json::to_vec(index)?.len() <= MAX_INDEX_BYTES {
        return Ok(());
    }
    let files = std::mem::take(&mut index.files);
    let total = files.len();
    let initial_omissions = index.omissions.index_limit;
    let mut low = 0_usize;
    let mut high = total.saturating_add(1);
    let mut best = None;
    while low < high {
        let retained = low + (high - low) / 2;
        index.files = files[..retained].to_vec();
        index.omissions.index_limit = initial_omissions + (total - retained) as u64;
        finalize_completeness(index);
        if serde_json::to_vec(index)?.len() <= MAX_INDEX_BYTES {
            best = Some(retained);
            low = retained.saturating_add(1);
        } else {
            high = retained;
        }
    }
    let retained = best.ok_or(RepositoryMapError::IndexTooLarge)?;
    index.files = files[..retained].to_vec();
    index.omissions.index_limit = initial_omissions + (total - retained) as u64;
    finalize_completeness(index);
    Ok(())
}
fn index_is_valid(index: &RepositoryMapIndex) -> bool {
    index
        .files
        .windows(2)
        .all(|window| window[0].path < window[1].path)
        && index.files.iter().all(|file| {
            is_safe_relative_path(&file.path)
                && file
                    .sha256
                    .as_ref()
                    .map_or(file.bytes > MAX_INDEXED_FILE_BYTES, |digest| {
                        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
        })
}
fn is_safe_relative_path(path: &str) -> bool {
    !path.starts_with('/')
        && !path.contains('\\')
        && path.as_bytes().get(1) != Some(&b':')
        && !path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
}
fn is_hidden_path(path: &str) -> bool {
    path.split('/').any(|component| component.starts_with('.'))
}
fn persist(state_dir: &Dir, index: &RepositoryMapIndex) -> Result<(), RepositoryMapError> {
    let raw = serde_json::to_vec(index)?;
    if raw.len() > MAX_INDEX_BYTES {
        return Err(RepositoryMapError::IndexTooLarge);
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = format!(".{INDEX_FILE}.{nonce}.tmp");
    state_dir.write(&temporary, raw)?;
    if let Err(error) = state_dir.rename(&temporary, state_dir, INDEX_FILE) {
        let _ = state_dir.remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}
fn total_inventory_paths(value: &RepositoryInventory) -> usize {
    value.source_paths.len()
        + value.test_paths.len()
        + value.manifest_paths.len()
        + value.configuration_paths.len()
}
fn bound_inventory(value: &mut RepositoryInventory) {
    while inventory_bytes(value).len() > MAX_INVENTORY_BYTES {
        if value.configuration_paths.pop().is_some()
            || value.manifest_paths.pop().is_some()
            || value.test_paths.pop().is_some()
            || value.source_paths.pop().is_some()
        {
            continue;
        }
        if let Some(package) = value.packages.last_mut()
            && package.targets.pop().is_some()
        {
            continue;
        }
        if value.packages.pop().is_some() {
            continue;
        }
        break;
    }
}
fn update_inventory_counts(value: &mut RepositoryInventory, index_omissions: u64) {
    value.projected_files = total_inventory_paths(value) as u64;
    value.omitted_files =
        index_omissions + value.indexed_files.saturating_sub(value.projected_files);
    value.omitted_packages = value
        .indexed_packages
        .saturating_sub(value.packages.len() as u64);
    let projected_targets = value
        .packages
        .iter()
        .map(|package| package.targets.len() as u64)
        .sum::<u64>();
    value.omitted_targets = value.indexed_targets.saturating_sub(projected_targets);
    value.projection_complete =
        value.omitted_files == 0 && value.omitted_packages == 0 && value.omitted_targets == 0;
}

#[cfg(test)]
mod tests;
