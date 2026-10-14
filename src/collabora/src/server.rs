use crate::graph::{Graph, Item};
use anyhow::{bail, Result};
use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Form, FromRequest, Query, Request, State,
    },
    http::{header, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

const SESSION_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);
const ONE_SHOT_LIFETIME: Duration = Duration::from_secs(60);
const MAX_DOCUMENT: usize = 250_000_000;
const MAX_RECOVERY_BYTES: u64 = 1_000_000_000;

#[derive(Clone)]
pub struct App {
    graph: Graph,
    bootstrap: String,
    address: SocketAddr,
    state: PathBuf,
    docs: Arc<Mutex<HashMap<String, Document>>>,
    uploads: Arc<Semaphore>,
    upload_body_timeout: Duration,
    connections: Arc<Semaphore>,
    downloads: Arc<Semaphore>,
    recovery_lock: Arc<Mutex<()>>,
    one_shots: Arc<Mutex<HashMap<String, OneShot>>>,
}

#[derive(Clone)]
struct Document {
    id: String,
    drive: String,
    item: String,
    name: String,
    etag: String,
    save_revision: Uuid,
    capability: String,
    expires: Instant,
    recoveries: Vec<PathBuf>,
    // Clones held by connected sockets and in-flight transfers pin the session.
    session_lease: Arc<()>,
}

impl Document {
    fn is_live(&self) -> bool {
        self.expires > Instant::now() || Arc::strong_count(&self.session_lease) > 1
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryMetadata {
    name: String,
    drive: String,
    item: String,
}

struct OneShot {
    doc: String,
    save_revision: Option<Uuid>,
    expires: Instant,
    kind: Kind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Fetch,
    Upload,
}

impl App {
    pub fn new(graph: Graph, bootstrap: String, address: SocketAddr, state: PathBuf) -> Self {
        Self {
            graph,
            bootstrap,
            address,
            state,
            docs: Arc::default(),
            uploads: Arc::new(Semaphore::new(1)),
            upload_body_timeout: Duration::from_secs(300),
            connections: Arc::new(Semaphore::new(64)),
            downloads: Arc::new(Semaphore::new(4)),
            recovery_lock: Arc::default(),
            one_shots: Arc::default(),
        }
    }
    pub fn router(self) -> Router {
        Router::new()
            .route("/", get(picker))
            .route("/picker.css", get(picker_css))
            .route("/picker.js", get(picker_js))
            .route("/open", get(open))
            .route("/recovery", get(recovery_picker))
            .route("/recovery/download", get(recovery_download))
            .route("/recovery/remove", post(recovery_remove))
            .route("/details", get(details))
            .route("/move", get(move_picker))
            .route("/action", post(action))
            .route("/co/collab", get(collab))
            .route("/co/collab/fetch", get(fetch))
            .route(
                "/co/collab/put",
                post(put)
                    .options(preflight)
                    .layer(DefaultBodyLimit::max(MAX_DOCUMENT)),
            )
            .with_state(self)
    }
    fn base(&self) -> String {
        format!("http://{}", self.address)
    }
    fn authorized(&self, query: &HashMap<String, String>) -> bool {
        query.get("k").is_some_and(|v| v == &self.bootstrap)
    }
    async fn document(&self, id: &str, capability: &str) -> Option<Document> {
        self.docs
            .lock()
            .await
            .get(id)
            .filter(|d| d.capability == capability && d.is_live())
            .cloned()
    }
    async fn issue(&self, id: String, kind: Kind) -> String {
        let token = Uuid::new_v4().to_string();
        let mut one_shots = self.one_shots.lock().await;
        let save_revision = self.docs.lock().await.get(&id).map(|doc| doc.save_revision);
        one_shots.retain(|_, entry| entry.expires > Instant::now());
        one_shots.insert(
            token.clone(),
            OneShot {
                doc: id,
                save_revision,
                kind,
                expires: Instant::now() + ONE_SHOT_LIFETIME,
            },
        );
        token
    }
    async fn consume(
        &self,
        token: &str,
        kind: Kind,
    ) -> Result<(Document, OwnedSemaphorePermit), StatusCode> {
        // Validate and admit atomically with consuming the capability. A busy
        // transfer must leave a valid URL available for a retry until expiry.
        let mut one_shots = self.one_shots.lock().await;
        let one = one_shots.get(token).ok_or(StatusCode::UNAUTHORIZED)?;
        if one.kind != kind || one.expires <= Instant::now() {
            one_shots.remove(token);
            return Err(StatusCode::UNAUTHORIZED);
        }
        // Hold the document state through admission so a successful save
        // cannot advance its revision between validation and acquiring capacity.
        let docs = self.docs.lock().await;
        let doc = docs.get(&one.doc).filter(|d| d.is_live()).cloned();
        let Some(doc) = doc else {
            one_shots.remove(token);
            return Err(StatusCode::UNAUTHORIZED);
        };
        if kind == Kind::Upload && one.save_revision != Some(doc.save_revision) {
            one_shots.remove(token);
            return Err(StatusCode::CONFLICT);
        }
        let capacity = match kind {
            Kind::Fetch => &self.downloads,
            Kind::Upload => &self.uploads,
        };
        let permit = capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        one_shots.remove(token);
        Ok((doc, permit))
    }
    async fn recovery(&self, doc: &Document, bytes: &[u8]) -> Result<PathBuf> {
        self.recovery_with_limit(doc, bytes, MAX_RECOVERY_BYTES)
            .await
    }
    async fn recovery_with_limit(
        &self,
        doc: &Document,
        bytes: &[u8],
        limit: u64,
    ) -> Result<PathBuf> {
        let doc_id = Uuid::parse_str(&doc.id)?;
        // Atomically replace only this session's latest unsaved copy.
        let _guard = self.recovery_lock.lock().await;
        tokio::fs::create_dir_all(&self.state).await?;
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&self.state, std::fs::Permissions::from_mode(0o700)).await?;
        let path = self.state.join(format!("recovery-{doc_id}.bin"));
        let temporary = self
            .state
            .join(format!(".recovery-{doc_id}-{}.tmp", Uuid::new_v4()));
        let metadata_path = path.with_extension("json");
        let metadata_temporary = temporary.with_extension("json.tmp");
        let metadata = serde_json::to_vec(&RecoveryMetadata {
            name: doc.name.clone(),
            drive: doc.drive.clone(),
            item: doc.item.clone(),
        })?;
        let mut entries = tokio::fs::read_dir(&self.state).await?;
        let mut count = 0;
        let mut used = 0u64;
        let mut cleaned = false;
        while let Some(entry) = entries.next_entry().await? {
            // The state-owner lock excludes other processes; recovery_lock
            // serializes this process's writers. Reclaim crash leftovers
            // before allocating another document-sized file,
            // but never remove ambiguous names, directories, or symlinks.
            if entry
                .file_name()
                .to_str()
                .is_some_and(recovery_temporary_name)
                && entry.file_type().await?.is_file()
            {
                tokio::fs::remove_file(entry.path()).await?;
                cleaned = true;
                continue;
            }
            if entry.path() != path
                && recovery_name(&entry.file_name().to_string_lossy())
                && entry.file_type().await?.is_file()
            {
                used = used.saturating_add(entry.metadata().await?.len());
                count += 1;
            }
        }
        if cleaned {
            // Failed cleanup/durability must leave every complete copy intact.
            tokio::fs::File::open(&self.state).await?.sync_all().await?;
        }
        if count >= 32 || used.saturating_add(bytes.len() as u64) > limit {
            bail!("Recovery quota reached; export existing recovery copies before removing them");
        }
        let result = async {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .await?;
            use tokio::io::AsyncWriteExt;
            file.write_all(bytes).await?;
            file.sync_all().await?;
            let mut metadata_file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&metadata_temporary)
                .await?;
            metadata_file.write_all(&metadata).await?;
            metadata_file.sync_all().await?;
            // Publish the session's source identity before its bytes. There are
            // deliberately no content-dependent fields (such as a timestamp):
            // if replacing the bytes fails, this still describes the old copy.
            // A metadata failure must never replace an existing recovery copy.
            let directory = tokio::fs::File::open(&self.state).await?;
            tokio::fs::rename(&metadata_temporary, &metadata_path).await?;
            directory.sync_all().await?;
            tokio::fs::rename(&temporary, &path).await?;
            directory.sync_all().await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(err) = result {
            let _ = tokio::fs::remove_file(&temporary).await;
            let _ = tokio::fs::remove_file(&metadata_temporary).await;
            if !tokio::fs::try_exists(&path).await.unwrap_or(true) {
                let _ = tokio::fs::remove_file(&metadata_path).await;
            }
            return Err(err);
        }
        Ok(path)
    }

    async fn remove_recovery(&self, path: &Path) -> std::io::Result<()> {
        let _guard = self.recovery_lock.lock().await;
        let removed = tokio::fs::remove_file(path).await;
        match &removed {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return removed,
            _ => {}
        }
        // Retry sidecar cleanup even if an earlier removal already deleted the
        // bytes but was interrupted before deleting their metadata.
        match tokio::fs::remove_file(path.with_extension("json")).await {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err),
            _ => {}
        }
        tokio::fs::File::open(&self.state).await?.sync_all().await?;
        removed
    }
}

async fn recovery_metadata(path: &Path) -> Option<RecoveryMetadata> {
    let bytes = tokio::fs::read(path.with_extension("json")).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn recovery_filename(name: &str) -> String {
    // Treat either platform's path separator as a basename boundary. Replace
    // control characters and filename metacharacters, including bidi overrides.
    let name: String = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_control()
                || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    let name = name.trim_matches([' ', '.']);
    if name.is_empty() {
        "recovered-document.bin".into()
    } else {
        name.into()
    }
}

fn recovery_disposition(name: &str) -> String {
    let name = recovery_filename(name);
    let fallback: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "attachment; filename=\"{fallback}\"; filename*=UTF-8''{}",
        enc(&name)
    )
}

fn recovery_temporary_name(name: &str) -> bool {
    let Some(stem) = name.strip_prefix(".recovery-").and_then(|name| {
        name.strip_suffix(".json.tmp")
            .or_else(|| name.strip_suffix(".tmp"))
    }) else {
        return false;
    };
    if stem.len() != 73 || stem.get(36..37) != Some("-") {
        return false;
    }
    [stem.get(..36), stem.get(37..)].into_iter().all(|part| {
        part.is_some_and(|part| {
            Uuid::parse_str(part).is_ok_and(|id| id.hyphenated().to_string() == part)
        })
    })
}

fn recovery_name(name: &str) -> bool {
    name.strip_prefix("recovery-")
        .and_then(|s| s.strip_suffix(".bin"))
        .is_some_and(|id| Uuid::parse_str(id).is_ok())
}

async fn recovery_picker(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !app.authorized(&q) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let _guard = app.recovery_lock.lock().await;
    let k = escape(&app.bootstrap);
    let mut body = format!("<p><a href='/?k={k}'>Files</a></p><p>These copies contain edits that could not be saved to Microsoft 365. Download and check a copy before removing it. Older copies without a saved filename need their original document extension restored. Recovery is limited to 32 documents and 1 GB; the latest failed save replaces the copy for that editor session.</p>");
    if let Ok(mut entries) = tokio::fs::read_dir(&app.state).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !recovery_name(&name) {
                continue;
            }
            let n = escape(&name);
            let label = recovery_metadata(&entry.path())
                .await
                .map(|metadata| escape(&metadata.name))
                .unwrap_or_else(|| n.clone());
            body.push_str(&format!("<p><a href='/recovery/download?k={k}&name={n}'>{label}</a></p><form method='post' action='/recovery/remove'><input type='hidden' name='k' value='{k}'><input type='hidden' name='name' value='{n}'><label><input type='checkbox' name='confirm' value='yes' required>I have recovered this copy</label> <button>Remove copy</button></form>"));
        }
    }
    private_html(page("Recovery copies", &body))
}

async fn recovery_download(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !app.authorized(&q) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(name) = q.get("name").filter(|name| recovery_name(name)) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(permit) = app.downloads.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (file, name) = {
        let _guard = app.recovery_lock.lock().await;
        let path = app.state.join(name);
        let Ok(file) = tokio::fs::File::open(&path).await else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let name = recovery_metadata(&path)
            .await
            .map(|metadata| metadata.name)
            .unwrap_or_else(|| name.clone());
        (file, name)
    };
    // The open file keeps this copy stable across replacement/removal. Release
    // the recovery lock now, but retain download admission until EOF or drop.
    let stream =
        futures_util::stream::try_unfold((file, permit), |(mut file, permit)| async move {
            use tokio::io::AsyncReadExt;
            let mut bytes = vec![0; 64 * 1024];
            let count = file.read(&mut bytes).await?;
            if count == 0 {
                Ok::<_, std::io::Error>(None)
            } else {
                bytes.truncate(count);
                Ok(Some((Bytes::from(bytes), (file, permit))))
            }
        });
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".into()),
            (header::CONTENT_DISPOSITION, recovery_disposition(&name)),
            (header::CACHE_CONTROL, "no-store".into()),
        ],
        axum::body::Body::from_stream(stream),
    )
        .into_response()
}

async fn recovery_remove(
    State(app): State<App>,
    Form(q): Form<HashMap<String, String>>,
) -> Response {
    if !app.authorized(&q) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(name) = q.get("name").filter(|name| recovery_name(name)) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if q.get("confirm").map(String::as_str) != Some("yes") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match app.remove_recovery(&app.state.join(name)).await {
        Ok(()) => Redirect::to(&format!("/recovery?k={}", enc(&app.bootstrap))).into_response(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn picker_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("picker.css"),
    )
        .into_response()
}

async fn picker_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("picker.js"),
    )
        .into_response()
}

pub async fn picker(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !app.authorized(&q) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match render_picker(&app, &q).await {
        Ok(html) => private_html(html),
        Err(err) => private_html(page(
            "Microsoft 365 unavailable",
            &format!(
                "<p>{}</p><p><a href='/recovery?k={}'>Recovery copies</a></p>",
                escape(&err.to_string()),
                enc(&app.bootstrap)
            ),
        )),
    }
}

async fn render_picker(app: &App, q: &HashMap<String, String>) -> Result<String> {
    let can_search_sites = app.graph.can_search_sites().await?;
    render_picker_with_consent(app, q, can_search_sites).await
}

async fn render_picker_with_consent(
    app: &App,
    q: &HashMap<String, String>,
    can_search_sites: bool,
) -> Result<String> {
    match render_picker_view(app, q, can_search_sites).await {
        Ok(html) => Ok(html),
        Err(err) => Ok(page(
            "Microsoft 365 unavailable",
            &format!(
                "<nav aria-label='File locations'>{}</nav><p>{}</p>{}",
                location_navigation(&app.bootstrap, "", can_search_sites),
                escape(&err.to_string()),
                sharing_link_form(&app.bootstrap)
            ),
        )),
    }
}

async fn render_picker_view(
    app: &App,
    q: &HashMap<String, String>,
    can_search_sites: bool,
) -> Result<String> {
    let view = q.get("view").map(String::as_str).unwrap_or("drive");
    let k = &app.bootstrap;
    let mut content = String::new();
    let heading: String;
    let mut search_placeholder = "Search OneDrive";
    let search = q.get("q").map(String::as_str).unwrap_or("").trim();
    let mut search_context: Vec<(&str, &str)> = Vec::new();
    let drive_id = if matches!(view, "drive" | "folder") {
        Some(match q.get("drive") {
            Some(id) => id.clone(),
            None => app.graph.own_drive().await?.id,
        })
    } else {
        None
    };
    match view {
        "drive" | "folder" => {
            let drive = drive_id.as_deref().unwrap_or_default();
            let parent = q.get("parent").map(String::as_str).unwrap_or("root");
            let mut context = Vec::new();
            for key in ["site", "site_name", "library_name"] {
                if let Some(value) = q.get(key) {
                    context.push((key, value.as_str()));
                }
            }
            let root_name = q
                .get("library_name")
                .map(String::as_str)
                .unwrap_or("OneDrive");
            heading = root_name.to_owned();
            search_placeholder = "Search this drive";
            search_context.extend([("view", "folder"), ("drive", drive), ("parent", parent)]);
            search_context.extend(context.iter().copied());
            content.push_str(&breadcrumbs(app, drive, parent, root_name, k, &context).await?);
            if search.is_empty() {
                content.push_str(&new_document_form(k, drive, parent, &context));
            }
            let items = if search.is_empty() {
                app.graph.children(drive, parent).await?
            } else {
                content.push_str(&format!(
                    "<p class='result-label'>Results for <strong>{}</strong> in {}</p>",
                    escape(search),
                    escape(root_name)
                ));
                app.graph.search_drive(drive, search).await?
            };
            content.push_str(&rows(items, drive, k, &context, search.is_empty())?);
        }
        "sites" => {
            heading = "SharePoint sites".to_owned();
            search_placeholder = "Search sites";
            search_context.push(("view", "sites"));
            content.push_str(
                "<nav class='breadcrumbs' aria-label='Folder path'><span>SharePoint</span></nav>",
            );
            if !search.is_empty() {
                let sites = app.graph.sites(search).await?;
                if sites.is_empty() {
                    content.push_str(&empty_state("No sites found", "Try another site name."));
                }
                for site in sites {
                    let name = site
                        .display_name
                        .as_deref()
                        .or(site.name.as_deref())
                        .unwrap_or("Site");
                    let label = escape(name);
                    let url =
                        picker_url(k, "libraries", &[("site", &site.id), ("site_name", name)]);
                    content.push_str(&format!("<a class='location-row' href='{}'><span class='file-icon site' aria-hidden='true'>S</span><span>{label}</span><span class='chevron' aria-hidden='true'>›</span></a>", escape(&url)));
                }
            } else {
                content.push_str(&empty_state(
                    "Find a SharePoint site",
                    "Search by site name to browse its document libraries.",
                ));
            }
        }
        "libraries" => {
            let site = q
                .get("site")
                .ok_or_else(|| anyhow::anyhow!("Missing site"))?;
            heading = q
                .get("site_name")
                .cloned()
                .unwrap_or_else(|| "Document libraries".to_owned());
            content.push_str(&format!("<nav class='breadcrumbs' aria-label='Folder path'><a href='{}'>SharePoint</a><span aria-hidden='true'>›</span><span>{}</span></nav>", escape(&picker_url(k, "sites", &[])), escape(&heading)));
            let drives = app.graph.drives(site).await?;
            if drives.is_empty() {
                content.push_str(&empty_state(
                    "No document libraries",
                    "This site has no libraries you can browse.",
                ));
            }
            for drive in drives {
                let name = drive.name.as_deref().unwrap_or("Documents");
                let url = picker_url(
                    k,
                    "folder",
                    &[
                        ("drive", &drive.id),
                        ("parent", "root"),
                        ("site", site),
                        ("site_name", &heading),
                        ("library_name", name),
                    ],
                );
                content.push_str(&format!("<a class='location-row' href='{}'><span class='file-icon folder' aria-hidden='true'></span><span>{}</span><span class='chevron' aria-hidden='true'>›</span></a>", escape(&url), escape(name)));
            }
        }
        "shared" => {
            heading = "Shared files".to_owned();
            search_placeholder = "Search shared files";
            search_context.push(("view", "shared"));
            if !search.is_empty() {
                content.push_str(&rows(
                    app.graph.shared_search(search).await?,
                    "",
                    k,
                    &[("library_name", "Shared files")],
                    false,
                )?);
            } else {
                content.push_str(&empty_state(
                    "Find a shared file",
                    "Search by file name, or open a sharing link below.",
                ));
            }
        }
        _ => bail!("Unknown picker view"),
    }
    let mut search_form = String::new();
    if view != "libraries" {
        search_form = format!("<form class='search' action='/' method='get' role='search'><input type='hidden' name='k' value='{}'>", escape(k));
        for (name, value) in search_context {
            search_form.push_str(&format!(
                "<input type='hidden' name='{}' value='{}'>",
                escape(name),
                escape(value)
            ));
        }
        search_form.push_str(&format!("<label class='sr-only' for='file-search'>{}</label><input id='file-search' name='q' value='{}' placeholder='{}' autocomplete='off'><button type='submit'>Search</button></form>", escape(search_placeholder), escape(search), escape(search_placeholder)));
    }
    let active = if view == "sites" || view == "libraries" || q.contains_key("site") {
        "sites"
    } else if view == "shared" {
        "shared"
    } else {
        "drive"
    };
    let nav = location_navigation(k, active, can_search_sites);
    let share_form = sharing_link_form(k);
    let body = format!("<div class='picker'><aside class='sidebar'><div class='brand'><span class='brand-mark' aria-hidden='true'>M</span><span>Microsoft 365</span></div><nav aria-label='File locations'>{nav}</nav><div class='sidebar-note'>Open or create cloud files in Collabora Office</div></aside><main class='workspace'><header class='topbar'><div><p class='eyebrow'>MICROSOFT 365 FILES</p><h1>{}</h1></div>{search_form}</header><div class='browser'><div class='browser-main'>{content}{share_form}</div><aside id='details-pane' class='details-pane' aria-label='File details' aria-live='polite'><button id='close-details' class='close-details' type='button' aria-label='Close file details'>×</button><div class='details-empty'><span class='details-symbol' aria-hidden='true'>▤</span><h2>No file selected</h2><p>Select a file to see its details and actions.</p></div></aside></div><footer class='footer'><span id='selection-status' role='status'>Select a file to open</span><button id='open-selected' type='button' disabled>Open</button></footer></main></div>", escape(&heading));
    Ok(document_page("Microsoft 365 files", &body))
}

fn new_document_form(k: &str, drive: &str, parent: &str, context: &[(&str, &str)]) -> String {
    let mut fields = format!("<input type='hidden' name='k' value='{}'><input type='hidden' name='op' value='create'><input type='hidden' name='drive' value='{}'><input type='hidden' name='parent' value='{}'>", escape(k), escape(drive), escape(parent));
    for (key, value) in context {
        fields.push_str(&format!(
            "<input type='hidden' name='{}' value='{}'>",
            escape(key),
            escape(value)
        ));
    }
    format!("<details class='new-document'><summary>New document</summary><form method='post' action='/action'>{fields}<label for='new-document-type'>Type</label><select id='new-document-type' name='type'><option value='word'>Word (.docx)</option><option value='excel'>Excel (.xlsx)</option><option value='powerpoint'>PowerPoint (.pptx)</option></select><label for='new-document-name'>Name (without extension)</label><input id='new-document-name' name='name' required maxlength='200' autocomplete='off'><button type='submit'>Create and open</button></form></details>")
}

fn sharing_link_form(k: &str) -> String {
    format!("<section class='share-link'><details><summary>Open a sharing link</summary><form action='/open' method='get'><input type='hidden' name='k' value='{}'><label for='share-url'>Paste a OneDrive or SharePoint link</label><div class='inline-form'><input id='share-url' name='share' type='url' placeholder='https://…' required><button type='submit'>Open</button></div></form></details></section>", escape(k))
}

fn location_navigation(k: &str, active: &str, can_search_sites: bool) -> String {
    let mut locations = vec![("drive", "OneDrive", picker_url(k, "drive", &[]))];
    if can_search_sites {
        locations.push(("sites", "SharePoint", picker_url(k, "sites", &[])));
    }
    locations.push(("shared", "Shared files", picker_url(k, "shared", &[])));
    locations.push((
        "recovery",
        "Recovery copies",
        format!("/recovery?k={}", enc(k)),
    ));
    locations
        .into_iter()
        .map(|(id, label, url)| {
            format!(
                "<a class='nav-link {}' {} href='{}'>{label}</a>",
                if active == id { "active" } else { "" },
                if active == id {
                    "aria-current='page'"
                } else {
                    ""
                },
                escape(&url)
            )
        })
        .collect()
}

fn rows(
    mut items: Vec<Item>,
    fallback_drive: &str,
    k: &str,
    context: &[(&str, &str)],
    browsing: bool,
) -> Result<String> {
    items.sort_by(|a, b| {
        let a_folder =
            a.folder.is_some() || a.remote_item.as_ref().is_some_and(|r| r.folder.is_some());
        let b_folder =
            b.folder.is_some() || b.remote_item.as_ref().is_some_and(|r| r.folder.is_some());
        b_folder
            .cmp(&a_folder)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    let mut result = String::from("<section class='file-list' role='listbox' aria-label='Files and folders'><div class='list-heading' role='presentation'><span>Name</span><span>Modified</span><span>Size</span></div>");
    let mut count = 0;
    for item in items {
        let (drive, id) = item.location(fallback_drive)?;
        let label = escape(&item.name);
        let folder = item.folder.is_some()
            || item
                .remote_item
                .as_ref()
                .is_some_and(|r| r.folder.is_some());
        let file =
            item.file.is_some() || item.remote_item.as_ref().is_some_and(|r| r.file.is_some());
        if folder {
            let mut args = vec![("drive", drive.as_str()), ("parent", id.as_str())];
            args.extend_from_slice(context);
            let url = picker_url(k, "folder", &args);
            result.push_str(&format!("<a class='file-row folder-row' role='option' aria-selected='false' href='{}'><span class='name-cell'><span class='file-icon folder' aria-hidden='true'></span><span class='file-name'>{label}</span></span><span class='muted'>{}</span><span class='muted'>Folder</span></a>", escape(&url), display_date(item.last_modified_date_time.as_deref())));
            count += 1;
        } else if file {
            let open = format!("/open?k={}&drive={}&item={}", enc(k), enc(&drive), enc(&id));
            let details = format!(
                "/details?k={}&drive={}&item={}{}",
                enc(k),
                enc(&drive),
                enc(&id),
                context_suffix(context)
            );
            let kind = file_kind(&item.name);
            result.push_str(&format!("<a class='file-row selectable' role='option' aria-selected='false' href='{}' data-open='{}' data-details='{}' data-name='{label}' aria-label='Select {label}'><span class='name-cell'><span class='file-icon {kind}' aria-hidden='true'>{}</span><span class='file-name'>{label}</span></span><span class='muted'>{}</span><span class='muted'>{}</span></a>", escape(&details), escape(&open), escape(&details), file_icon_text(kind), display_date(item.last_modified_date_time.as_deref()), format_size(item.size)));
            count += 1;
        }
    }
    result.push_str("</section>");
    if count == 0 {
        result.push_str(&empty_state(
            if browsing {
                "This folder is empty"
            } else {
                "No matching files"
            },
            if browsing {
                "Choose another location or search this drive."
            } else {
                "Try a different search term."
            },
        ));
    }
    Ok(result)
}

fn picker_url(k: &str, view: &str, params: &[(&str, &str)]) -> String {
    let mut url = format!("/?k={}&view={}", enc(k), enc(view));
    for (name, value) in params {
        url.push_str(&format!("&{}={}", enc(name), enc(value)));
    }
    url
}

fn context_suffix(context: &[(&str, &str)]) -> String {
    context
        .iter()
        .map(|(name, value)| format!("&{}={}", enc(name), enc(value)))
        .collect()
}
fn context_from_query(q: &HashMap<String, String>) -> Vec<(&str, &str)> {
    ["site", "site_name", "library_name"]
        .into_iter()
        .filter_map(|key| q.get(key).map(|value| (key, value.as_str())))
        .collect()
}

async fn breadcrumbs(
    app: &App,
    drive: &str,
    parent: &str,
    root_name: &str,
    k: &str,
    context: &[(&str, &str)],
) -> Result<String> {
    let mut result = String::from("<nav class='breadcrumbs' aria-label='Folder path'>");
    if let Some((_, site)) = context.iter().find(|(name, _)| *name == "site") {
        let site_name = context
            .iter()
            .find(|(name, _)| *name == "site_name")
            .map(|(_, name)| *name)
            .unwrap_or("SharePoint");
        let url = picker_url(k, "libraries", &[("site", site), ("site_name", site_name)]);
        result.push_str(&format!(
            "<a href='{}'>{}</a><span aria-hidden='true'>›</span>",
            escape(&url),
            escape(site_name)
        ));
    }
    let mut root_args = vec![("drive", drive), ("parent", "root")];
    root_args.extend_from_slice(context);
    let root_url = picker_url(k, "folder", &root_args);
    result.push_str(&format!(
        "<a href='{}'>{}</a>",
        escape(&root_url),
        escape(root_name)
    ));
    if parent != "root" {
        let root_id = app.graph.root(drive).await?.id;
        let mut current = parent.to_owned();
        let mut seen = HashSet::new();
        let mut path = Vec::new();
        for _ in 0..32 {
            if current == root_id || !seen.insert(current.clone()) {
                break;
            }
            let folder = app.graph.item(drive, &current).await?;
            let next = folder.parent_reference.and_then(|p| p.id);
            path.push((folder.name, current));
            match next {
                Some(id) => current = id,
                None => break,
            }
        }
        path.reverse();
        for (name, id) in path {
            let mut args = vec![("drive", drive), ("parent", id.as_str())];
            args.extend_from_slice(context);
            let url = picker_url(k, "folder", &args);
            result.push_str(&format!(
                "<span aria-hidden='true'>›</span><a href='{}'>{}</a>",
                escape(&url),
                escape(&name)
            ));
        }
    }
    result.push_str("</nav>");
    Ok(result)
}

fn empty_state(title: &str, hint: &str) -> String {
    format!("<div class='empty-state'><span class='empty-symbol' aria-hidden='true'>◇</span><h2>{}</h2><p>{}</p></div>", escape(title), escape(hint))
}

fn display_date(value: Option<&str>) -> String {
    value
        .map(|date| escape(&date.chars().take(10).collect::<String>()))
        .unwrap_or_else(|| "—".to_owned())
}

fn format_size(value: Option<u64>) -> String {
    let Some(bytes) = value else {
        return "—".to_owned();
    };
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut size = bytes as f64;
    let mut unit = "B";
    for next in ["KB", "MB", "GB", "TB"] {
        size /= 1024.0;
        unit = next;
        if size < 1024.0 {
            break;
        }
    }
    format!("{size:.1} {unit}")
}

fn file_kind(name: &str) -> &'static str {
    match name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "doc" | "docx" | "odt" => "word",
        "xls" | "xlsx" | "ods" => "sheet",
        "ppt" | "pptx" | "odp" => "slides",
        "pdf" => "pdf",
        _ => "generic",
    }
}

fn file_icon_text(kind: &str) -> &'static str {
    match kind {
        "word" => "W",
        "sheet" => "X",
        "slides" => "P",
        "pdf" => "PDF",
        _ => "·",
    }
}

pub async fn open(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !app.authorized(&q) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let result: Result<Item> = if let Some(link) = q.get("share") {
        app.graph.resolve_share(link).await
    } else if let (Some(drive), Some(item)) = (q.get("drive"), q.get("item")) {
        app.graph.item(drive, item).await
    } else {
        Err(anyhow::anyhow!("Missing file"))
    };
    match result {
        Ok(item) => {
            let (drive, id) = match item.location(q.get("drive").map(String::as_str).unwrap_or(""))
            {
                Ok(x) => x,
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            };
            let Some(etag) = item.etag else {
                return StatusCode::CONFLICT.into_response();
            };
            let doc_id = Uuid::new_v4().to_string();
            let capability = Uuid::new_v4().to_string();
            let doc = Document {
                id: doc_id.clone(),
                drive,
                item: id,
                name: item.name,
                etag,
                save_revision: Uuid::new_v4(),
                capability: capability.clone(),
                expires: Instant::now() + SESSION_LIFETIME,
                recoveries: Vec::new(),
                session_lease: Arc::new(()),
            };
            let mut docs = app.docs.lock().await;
            docs.retain(|_, entry| entry.is_live());
            docs.insert(doc_id.clone(), doc);
            let wopi = format!("{}/wopi/{doc_id}", app.base());
            // IntegratorFilePicker::acceptNavigationRequest intercepts WOPISrc
            // and opens the bundled desktop editor; this is not an asset URL
            // fetched from our HTTP server.
            let target = format!(
                "{}/browser/dist/cool.html?WOPISrc={}&access_token={}",
                app.base(),
                enc(&wopi),
                enc(&capability)
            );
            Redirect::to(&target).into_response()
        }
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

pub async fn details(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !app.authorized(&q) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Some(drive), Some(id)) = (q.get("drive"), q.get("item")) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let item = match app.graph.item(drive, id).await {
        Ok(item) => item,
        Err(err) => return (StatusCode::BAD_GATEWAY, err.to_string()).into_response(),
    };
    let k = escape(&app.bootstrap);
    let d = escape(drive);
    let i = escape(id);
    let n = escape(&item.name);
    let context = context_from_query(&q);
    let mut fields = format!("<input type='hidden' name='k' value='{k}'><input type='hidden' name='drive' value='{d}'><input type='hidden' name='item' value='{i}'>");
    for (name, value) in &context {
        fields.push_str(&format!(
            "<input type='hidden' name='{}' value='{}'>",
            escape(name),
            escape(value)
        ));
    }
    let open_url = format!(
        "/open?k={}&drive={}&item={}",
        enc(&app.bootstrap),
        enc(drive),
        enc(id)
    );
    let move_url = format!(
        "/move?k={}&drive={}&item={}{}",
        enc(&app.bootstrap),
        enc(drive),
        enc(id),
        context_suffix(&context)
    );
    let mut body = format!("<div class='detail-content'><div class='detail-head'><span class='file-icon {}' aria-hidden='true'>{}</span><div><p class='eyebrow'>FILE DETAILS</p><h2>{n}</h2></div></div><dl class='metadata'><div><dt>Size</dt><dd>{}</dd></div><div><dt>Modified</dt><dd>{}</dd></div></dl><a class='primary-link' href='{}'>Open in Collabora</a><div class='detail-actions'><h3>File actions</h3>", file_kind(&item.name), file_icon_text(file_kind(&item.name)), format_size(item.size), display_date(item.last_modified_date_time.as_deref()), escape(&open_url));
    body.push_str(&format!("<details><summary>Rename</summary><form method='post' action='/action'>{fields}<input type='hidden' name='op' value='rename'><label for='rename-name'>New name</label><input id='rename-name' name='name' value='{n}' required><button>Rename</button></form></details>"));
    body.push_str(&format!("<details><summary>Save a copy</summary><p>Copies the latest saved cloud version into the same folder.</p><form method='post' action='/action'>{fields}<input type='hidden' name='op' value='save_as'><label for='copy-name'>Copy name</label><input id='copy-name' name='name' value='Copy of {n}' required><button>Save copy</button></form></details>"));
    body.push_str(&format!(
        "<a class='action-link' href='{}'>Move to folder</a>",
        escape(&move_url)
    ));
    body.push_str(&format!("<details><summary>Check out or check in</summary><form method='post' action='/action'>{fields}<div class='button-row'><button name='op' value='checkout'>Check out</button><button name='op' value='checkin'>Check in</button></div></form></details>"));
    body.push_str(&format!("<details class='danger-action'><summary>Delete</summary><form method='post' action='/action'>{fields}<label class='confirm'><input type='checkbox' name='confirm' value='yes' required> Move file to recycle bin</label><button name='op' value='delete'>Delete file</button></form></details></div><section class='versions'><h3>Versions</h3>"));
    match app.graph.versions(drive, id).await {
        Ok(versions) => {
            if versions.is_empty() {
                body.push_str("<p class='muted'>No versions available.</p>");
            }
            for version in versions {
                body.push_str(&format!(
                    "<div class='version-row'><strong>{}</strong><span>{}</span><span>{}</span></div>",
                    escape(&version.id),
                    display_date(version.last_modified_date_time.as_deref()),
                    format_size(version.size)
                ));
            }
        }
        Err(err) => body.push_str(&format!(
            "<p class='muted'>Versions unavailable: {}</p>",
            escape(&err.to_string())
        )),
    }
    body.push_str("</section></div>");
    if q.get("panel").map(String::as_str) == Some("1") {
        private_html(body)
    } else {
        let parent = item
            .parent_reference
            .as_ref()
            .and_then(|p| p.id.as_deref())
            .unwrap_or("root");
        let mut args = vec![("drive", drive.as_str()), ("parent", parent)];
        args.extend_from_slice(&context);
        let back_url = picker_url(&app.bootstrap, "folder", &args);
        private_html(page(
            &item.name,
            &format!("<p><a href='{}'>← Files</a></p>{body}", escape(&back_url)),
        ))
    }
}

pub async fn move_picker(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !app.authorized(&q) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Some(drive), Some(item)) = (q.get("drive"), q.get("item")) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let parent = if let Some(parent) = q.get("parent") {
        parent.clone()
    } else {
        match app.graph.item(drive, item).await {
            Ok(source) => source
                .parent_reference
                .and_then(|p| p.id)
                .unwrap_or("root".into()),
            Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
        }
    };
    let children = match app.graph.children(drive, &parent).await {
        Ok(items) => items,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let context = context_from_query(&q);
    let suffix = context_suffix(&context);
    let base = format!(
        "/move?k={}&drive={}&item={}{}",
        enc(&app.bootstrap),
        enc(drive),
        enc(item),
        suffix
    );
    let details_url = format!(
        "/details?k={}&drive={}&item={}{}",
        enc(&app.bootstrap),
        enc(drive),
        enc(item),
        suffix
    );
    let mut fields = format!("<input type='hidden' name='k' value='{}'><input type='hidden' name='drive' value='{}'><input type='hidden' name='item' value='{}'><input type='hidden' name='parent' value='{}'>", escape(&app.bootstrap), escape(drive), escape(item), escape(&parent));
    for (name, value) in &context {
        fields.push_str(&format!(
            "<input type='hidden' name='{}' value='{}'>",
            escape(name),
            escape(value)
        ));
    }
    let mut body = format!("<p><a href='{}'>← Back to file</a></p><p class='muted'>Choose a folder in this drive.</p><form method='post' action='/action'>{fields}<button class='destination-button' name='op' value='move'>Move here</button></form><div class='destination-list'>", escape(&details_url));
    if parent != "root" {
        if let Ok(folder) = app.graph.item(drive, &parent).await {
            let ancestor = folder
                .parent_reference
                .and_then(|p| p.id)
                .unwrap_or("root".into());
            body.push_str(&format!(
                "<a class='location-row' href='{}&amp;parent={}'>↑ Parent folder</a>",
                escape(&base),
                enc(&ancestor)
            ));
        }
    }
    for child in children.into_iter().filter(|i| i.folder.is_some()) {
        body.push_str(&format!("<a class='location-row' href='{}&amp;parent={}'><span class='file-icon folder' aria-hidden='true'></span><span>{}</span><span class='chevron' aria-hidden='true'>›</span></a>", escape(&base), enc(&child.id), escape(&child.name)));
    }
    body.push_str("</div>");
    private_html(page("Choose destination", &body))
}

pub async fn collab(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Response {
    let id = q
        .get("WOPISrc")
        .and_then(|s| s.rsplit('/').next())
        .unwrap_or("")
        .to_owned();
    if Uuid::parse_str(&id).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(permit) = app.connections.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(64 * 1024)
        .max_frame_size(64 * 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            socket_loop(app, id, socket).await;
        })
        .into_response()
}

async fn socket_loop(app: App, id: String, mut socket: WebSocket) {
    let Ok(Some(Ok(Message::Text(first)))) =
        tokio::time::timeout(Duration::from_secs(5), socket.next()).await
    else {
        return;
    };
    let Some(capability) = first.strip_prefix("access_token ") else {
        return;
    };
    let Some(doc) = app.document(&id, capability).await else {
        let _ = socket
            .send(Message::Text("error: cmd=collab kind=accesstoken".into()))
            .await;
        return;
    };
    tracing::info!("Collabora document session connected");
    let _ = socket
        .send(Message::Text(
            json!({"type":"authenticated"}).to_string().into(),
        ))
        .await;
    let _ = socket
        .send(Message::Text(
            json!({"type":"user_list","users":[],"editingActive":false})
                .to_string()
                .into(),
        ))
        .await;
    while let Some(Ok(message)) = socket.next().await {
        let text = match message {
            Message::Text(text) => text,
            Message::Binary(_) => {
                let _ = socket.send(Message::Text(json!({"type":"error","error":"Unsupported Collabora protocol: expected a JSON text message"}).to_string().into())).await;
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
        };
        let available = {
            let mut docs = app.docs.lock().await;
            if let Some(current) = docs.get_mut(&id) {
                current.expires = Instant::now() + SESSION_LIFETIME;
                true
            } else {
                false
            }
        };
        if !available {
            let _ = socket.send(Message::Text(json!({"type":"error","error":"Document session is unavailable. Keep the document open and export a local copy."}).to_string().into())).await;
            break;
        }
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            let _ = socket.send(Message::Text(json!({"type":"error","error":"Unsupported Collabora protocol: expected a JSON message"}).to_string().into())).await;
            break;
        };
        let stream = value.get("stream").and_then(Value::as_str).unwrap_or("");
        let request = value.get("requestId").and_then(Value::as_str).unwrap_or("");
        let supported = match value.get("type").and_then(Value::as_str) {
            Some("fetch" | "upload") => matches!(stream, "contents" | "document"),
            Some("bye" | "editing_started") => true,
            _ => false,
        };
        let reply = match value.get("type").and_then(Value::as_str) {
            Some("fetch") if matches!(stream, "contents" | "document") => {
                let token = app.issue(id.clone(), Kind::Fetch).await;
                json!({"type":"fetch_url","stream":stream,"requestId":request,
                    "url":format!("/co/collab/fetch?token={token}"),"filename":doc.name})
            }
            Some("upload") if matches!(stream, "contents" | "document") => {
                tracing::info!("Collabora requested a document upload URL");
                let token = app.issue(id.clone(), Kind::Upload).await;
                json!({"type":"upload_url","stream":stream,"requestId":request,
                    "url":format!("/co/collab/put?token={token}")})
            }
            Some("bye") => break,
            Some("editing_started") => continue,
            _ => json!({"type":"error","error":"Unsupported Collabora protocol message or stream"}),
        };
        if socket
            .send(Message::Text(reply.to_string().into()))
            .await
            .is_err()
        {
            break;
        }
        if !supported {
            break;
        }
    }
    tracing::info!("Collabora document session disconnected");
}

pub async fn fetch(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some(token) = q.get("token") else {
        return cors_response(StatusCode::UNAUTHORIZED);
    };
    let (doc, permit) = match app.consume(token, Kind::Fetch).await {
        Ok(admitted) => admitted,
        Err(status) => return cors_response(status),
    };
    match app.graph.download(&doc.drive, &doc.item).await {
        Ok(download) => {
            // Own the admission permit and document lease until the body
            // finishes or the client disconnects, not just until header time.
            let stream = futures_util::stream::try_unfold(
                (download, permit, doc),
                |(mut download, permit, doc)| async move {
                    match download.chunk().await? {
                        Some(part) => Ok::<_, anyhow::Error>(Some((part, (download, permit, doc)))),
                        None => Ok(None),
                    }
                },
            );
            let mut response = axum::body::Body::from_stream(stream).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            cors(&mut response);
            response
        }
        Err(_) => cors_response(StatusCode::BAD_GATEWAY),
    }
}

pub async fn put(
    State(app): State<App>,
    Query(q): Query<HashMap<String, String>>,
    request: Request,
) -> Response {
    let Some(token) = q.get("token") else {
        tracing::warn!("Collabora upload missing one-time token");
        return cors_response(StatusCode::UNAUTHORIZED);
    };
    // Admit at most one document body, including its cloud upload/recovery.
    // Queued HTTP requests must not buffer documents before serialization.
    let (doc, _upload) = match app.consume(token, Kind::Upload).await {
        Ok(admitted) => admitted,
        Err(status) => {
            tracing::warn!(%status, "Collabora upload was not admitted");
            return cors_response(status);
        }
    };
    // Authenticate before extracting the document-sized body. The route-local
    // limit is still enforced by Bytes, while other forms keep Axum's default.
    let body_future = Bytes::from_request(request, &app);
    let body = match tokio::time::timeout(app.upload_body_timeout, body_future).await {
        Ok(Ok(body)) => body,
        Ok(Err(rejection)) => return cors_response(rejection),
        Err(_) => {
            return cors_response((
                StatusCode::REQUEST_TIMEOUT,
                "Upload timed out. Keep the document open and retry the save.",
            ))
        }
    };
    if body.len() > MAX_DOCUMENT {
        tracing::warn!(bytes = body.len(), "Collabora upload exceeds bridge limit");
        return cors_response(StatusCode::PAYLOAD_TOO_LARGE);
    }
    tracing::info!(bytes = body.len(), "Collabora sent edited document bytes");
    let result = app
        .graph
        .replace(&doc.drive, &doc.item, &doc.etag, body.clone())
        .await;
    let mut response = match result {
        Ok(saved) => {
            let recoveries = {
                let mut docs = app.docs.lock().await;
                if let Some(current) = docs.values_mut().find(|d| d.capability == doc.capability) {
                    // Invalidate older upload URLs even if Graph omits eTag.
                    current.save_revision = Uuid::new_v4();
                    if let Some(tag) = saved.etag {
                        current.etag = tag;
                    }
                    std::mem::take(&mut current.recoveries)
                } else {
                    Vec::new()
                }
            };
            for path in recoveries {
                if app.remove_recovery(&path).await.is_err() {
                    tracing::warn!("Unable to remove superseded recovery copy");
                }
            }
            axum::Json(json!({"success":true})).into_response()
        }
        Err(err) => {
            tracing::warn!("Microsoft 365 save failed: {err}");
            match app.recovery(&doc, &body).await {
                Ok(path) => {
                    if let Some(current) = app
                        .docs
                        .lock()
                        .await
                        .values_mut()
                        .find(|d| d.capability == doc.capability)
                    {
                        if !current.recoveries.contains(&path) {
                            current.recoveries.push(path.clone());
                        }
                    }
                    (StatusCode::CONFLICT, axum::Json(json!({
                        "success":false,
                        "error":format!("Save failed; edited copy preserved at {}", path.display()),
                        "recoveryPath":path
                    }))).into_response()
                }
                Err(recovery_error) => {
                    tracing::error!("Unable to preserve failed save: {recovery_error}");
                    (StatusCode::INSUFFICIENT_STORAGE, axum::Json(json!({
                        "success":false,
                        "error":"Save and recovery failed. Keep the document open and export a local copy before closing it. Check free disk space and the recovery quota."
                    }))).into_response()
                }
            }
        }
    };
    cors(&mut response);
    response
}

pub async fn preflight() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    cors(&mut response);
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type"),
    );
    response
}

pub async fn action(State(app): State<App>, Form(f): Form<HashMap<String, String>>) -> Response {
    if !app.authorized(&f) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if f.get("op").map(String::as_str) == Some("create") {
        return create_document(&app, &f).await;
    }
    let (Some(drive), Some(item)) = (f.get("drive"), f.get("item")) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let current = match app.graph.item(drive, item).await {
        Ok(item) => item,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let Some(etag) = current.etag else {
        return StatusCode::CONFLICT.into_response();
    };
    let result = match f.get("op").map(String::as_str) {
        Some("rename") => {
            let name = f.get("name").cloned().unwrap_or_default();
            if name.is_empty() || name.contains('/') {
                return StatusCode::BAD_REQUEST.into_response();
            }
            app.graph
                .update(drive, item, &etag, json!({"name":name}))
                .await
                .map(|_| ())
        }
        Some("save_as") => {
            let Ok(_upload) = app.uploads.clone().try_acquire_owned() else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let name = f.get("name").cloned().unwrap_or_default();
            let parent = current
                .parent_reference
                .as_ref()
                .and_then(|p| p.id.as_deref())
                .unwrap_or("root");
            if name.is_empty() || name.contains('/') || name == current.name {
                return StatusCode::BAD_REQUEST.into_response();
            }
            match app.graph.content(drive, item).await {
                Ok(bytes) => app
                    .graph
                    .create(drive, parent, &name, bytes.into())
                    .await
                    .map(|_| ()),
                Err(err) => Err(err),
            }
        }
        Some("move") => {
            let parent = f.get("parent").cloned().unwrap_or_default();
            if parent.is_empty() || parent == *item {
                return StatusCode::BAD_REQUEST.into_response();
            }
            let parent = if parent == "root" {
                match app.graph.root(drive).await {
                    Ok(root) => root.id,
                    Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
                }
            } else {
                parent
            };
            app.graph
                .update(drive, item, &etag, json!({"parentReference":{"id":parent}}))
                .await
                .map(|_| ())
        }
        Some("delete") if f.get("confirm").map(String::as_str) == Some("yes") => {
            app.graph.delete(drive, item, &etag).await
        }
        Some("checkout") => app.graph.checkout(drive, item, false).await,
        Some("checkin") => app.graph.checkout(drive, item, true).await,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    match result {
        Ok(()) => {
            let parent = if f.get("op").map(String::as_str) == Some("move") {
                f.get("parent").map(String::as_str).unwrap_or("root")
            } else {
                current
                    .parent_reference
                    .as_ref()
                    .and_then(|p| p.id.as_deref())
                    .unwrap_or("root")
            };
            Redirect::to(&format!(
                "/?k={}&view=folder&drive={}&parent={}{}",
                enc(&app.bootstrap),
                enc(drive),
                enc(parent),
                context_suffix(&context_from_query(&f))
            ))
            .into_response()
        }
        Err(err) => (StatusCode::CONFLICT, escape(&err.to_string())).into_response(),
    }
}

fn creation_error(
    app: &App,
    form: &HashMap<String, String>,
    status: StatusCode,
    message: &str,
) -> Response {
    let back = match (form.get("drive"), form.get("parent")) {
        (Some(drive), Some(parent)) => format!(
            "/?k={}&view=folder&drive={}&parent={}{}",
            enc(&app.bootstrap),
            enc(drive),
            enc(parent),
            context_suffix(&context_from_query(form))
        ),
        _ => format!("/?k={}", enc(&app.bootstrap)),
    };
    let body = format!(
        "<p role='alert'>{}</p><p><a href='{}'>Back to folder</a></p>",
        escape(message),
        escape(&back)
    );
    let mut response = private_html(page("Could not create document", &body));
    *response.status_mut() = status;
    response
}

async fn create_document(app: &App, form: &HashMap<String, String>) -> Response {
    let (Some(drive), Some(parent), Some(base)) = (
        form.get("drive").filter(|value| !value.is_empty()),
        form.get("parent").filter(|value| !value.is_empty()),
        form.get("name"),
    ) else {
        return creation_error(
            app,
            form,
            StatusCode::BAD_REQUEST,
            "Choose a folder and name.",
        );
    };
    let base = base.trim();
    if base.is_empty()
        || base.chars().count() > 200
        || base.ends_with('.')
        || base
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
    {
        return creation_error(app, form, StatusCode::BAD_REQUEST, "Invalid document name.");
    }
    let (extension, bytes): (&str, &'static [u8]) = match form.get("type").map(String::as_str) {
        Some("word") => ("docx", include_bytes!("../assets/blank.docx")),
        Some("excel") => ("xlsx", include_bytes!("../assets/blank.xlsx")),
        Some("powerpoint") => ("pptx", include_bytes!("../assets/blank.pptx")),
        _ => {
            return creation_error(
                app,
                form,
                StatusCode::BAD_REQUEST,
                "Choose a document type.",
            )
        }
    };
    let Ok(_upload) = app.uploads.clone().try_acquire_owned() else {
        return creation_error(
            app,
            form,
            StatusCode::SERVICE_UNAVAILABLE,
            "A document transfer is in progress. Try again shortly.",
        );
    };
    let name = format!("{base}.{extension}");
    match app
        .graph
        .create(drive, parent, &name, Bytes::from_static(bytes))
        .await
    {
        Ok(item) => match item.location(drive) {
            Ok((drive, id)) => Redirect::to(&format!(
                "/open?k={}&drive={}&item={}",
                enc(&app.bootstrap),
                enc(&drive),
                enc(&id)
            ))
            .into_response(),
            Err(err) => creation_error(app, form, StatusCode::BAD_GATEWAY, &err.to_string()),
        },
        Err(err) => creation_error(app, form, StatusCode::BAD_GATEWAY, &err.to_string()),
    }
}

fn page(title: &str, body: &str) -> String {
    document_page(
        title,
        &format!(
            "<main class='standalone-detail'><h1>{}</h1>{body}</main>",
            escape(title)
        ),
    )
}
fn document_page(title: &str, body: &str) -> String {
    format!("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><meta name='referrer' content='no-referrer'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'\"><title>{}</title><link rel='stylesheet' href='/picker.css'><script src='/picker.js' defer></script></head><body>{body}</body></html>", escape(title))
}
fn private_html(html: String) -> Response {
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn enc(input: &str) -> String {
    urlencoding::encode(input).into_owned()
}
fn cors(response: &mut Response) {
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn cors_response(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    cors(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CreateMock {
        origin: String,
        path: String,
        name: String,
        bytes: &'static [u8],
        conflict: bool,
        sessions: AtomicUsize,
        uploads: AtomicUsize,
    }

    async fn mock_create_session(
        State(mock): State<Arc<CreateMock>>,
        uri: axum::http::Uri,
        headers: HeaderMap,
        axum::Json(body): axum::Json<Value>,
    ) -> Response {
        assert_eq!(uri.path(), mock.path);
        assert_eq!(
            headers.get(header::AUTHORIZATION).unwrap(),
            "Bearer mock-token"
        );
        assert_eq!(body["item"]["name"], mock.name);
        assert_eq!(body["item"]["@microsoft.graph.conflictBehavior"], "fail");
        mock.sessions.fetch_add(1, Ordering::SeqCst);
        if mock.conflict {
            (
                StatusCode::CONFLICT,
                axum::Json(json!({"error":{"code":"nameAlreadyExists"}})),
            )
                .into_response()
        } else {
            axum::Json(json!({"uploadUrl":format!("{}/upload", mock.origin)})).into_response()
        }
    }

    async fn mock_create_upload(
        State(mock): State<Arc<CreateMock>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        assert!(!headers.contains_key(header::AUTHORIZATION));
        assert_eq!(body.as_ref(), mock.bytes);
        assert_eq!(
            headers
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes 0-{}/{}", body.len() - 1, body.len())
        );
        mock.uploads.fetch_add(1, Ordering::SeqCst);
        axum::Json(json!({"id":"created","name":mock.name,"eTag":"new"})).into_response()
    }

    async fn create_mock_app(
        drive: &str,
        parent: &str,
        name: &str,
        bytes: &'static [u8],
        conflict: bool,
    ) -> (App, Arc<CreateMock>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let path = if parent == "root" {
            format!(
                "/drives/{drive}/root:/{encoded}:/createUploadSession",
                encoded = enc(name)
            )
        } else {
            format!(
                "/drives/{drive}/items/{parent}:/{encoded}:/createUploadSession",
                encoded = enc(name)
            )
        };
        let mock = Arc::new(CreateMock {
            origin: origin.clone(),
            path,
            name: name.to_owned(),
            bytes,
            conflict,
            sessions: AtomicUsize::new(0),
            uploads: AtomicUsize::new(0),
        });
        let router = Router::new()
            .route("/upload", axum::routing::put(mock_create_upload))
            .fallback(post(mock_create_session))
            .with_state(mock.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let app = App::new(
            Graph::mock(reqwest::Url::parse(&origin).unwrap()),
            "bootstrap".into(),
            address,
            std::env::temp_dir().join(format!("collabora-create-{}", Uuid::new_v4())),
        );
        (app, mock, task)
    }

    struct Mock {
        mode: usize,
        origin: String,
        sessions: AtomicUsize,
        uploads: AtomicUsize,
        downloads: AtomicUsize,
    }

    async fn mock_item(State(mock): State<Arc<Mock>>) -> axum::Json<Value> {
        axum::Json(
            json!({"id":"item","name":"test.docx","eTag":if mock.mode == 0 {"new"} else {"old"}}),
        )
    }

    async fn mock_session(State(mock): State<Arc<Mock>>, headers: HeaderMap) -> Response {
        assert_eq!(headers.get(header::IF_MATCH).unwrap(), "old");
        assert_eq!(
            headers.get(header::AUTHORIZATION).unwrap(),
            "Bearer mock-token"
        );
        mock.sessions.fetch_add(1, Ordering::SeqCst);
        if mock.mode == 1 {
            (
                StatusCode::PRECONDITION_FAILED,
                axum::Json(json!({"error":{"code":"preconditionFailed"}})),
            )
                .into_response()
        } else {
            axum::Json(json!({"uploadUrl":format!("{}/upload", mock.origin)})).into_response()
        }
    }

    async fn mock_upload(
        State(mock): State<Arc<Mock>>,
        headers: HeaderMap,
        bytes: Bytes,
    ) -> Response {
        assert!(!headers.contains_key(header::AUTHORIZATION));
        assert_eq!(headers.get(header::CONTENT_RANGE).unwrap(), "bytes 0-4/5");
        assert_eq!(&bytes[..], b"edits");
        mock.uploads.fetch_add(1, Ordering::SeqCst);
        if mock.mode == 2 {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        } else if mock.mode == 6 {
            axum::Json(json!({"id":"item","name":"test.docx"})).into_response()
        } else {
            axum::Json(json!({"id":"item","name":"test.docx","eTag":"saved"})).into_response()
        }
    }

    async fn mock_download(State(mock): State<Arc<Mock>>) -> Response {
        mock.downloads.fetch_add(1, Ordering::SeqCst);
        if mock.mode == 4 {
            let pending = std::future::pending::<Result<Bytes, std::io::Error>>();
            axum::body::Body::from_stream(futures_util::stream::once(pending)).into_response()
        } else if mock.mode == 5 {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        } else {
            "document".into_response()
        }
    }

    async fn mock_app(mode: usize) -> (App, Arc<Mock>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let mock = Arc::new(Mock {
            mode,
            origin: origin.clone(),
            sessions: AtomicUsize::new(0),
            uploads: AtomicUsize::new(0),
            downloads: AtomicUsize::new(0),
        });
        let router = Router::new()
            .route("/drives/drive/items/item", get(mock_item))
            .route("/drives/drive/items/item/content", get(mock_download))
            .route(
                "/drives/drive/items/item/createUploadSession",
                post(mock_session),
            )
            .route("/upload", axum::routing::put(mock_upload))
            .route(
                "/drives/drive/root/children",
                get(|| async { axum::Json(json!({"value":[]})) }),
            )
            .with_state(mock.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let state = std::env::temp_dir().join(format!("collabora-save-{}", Uuid::new_v4()));
        let app = App::new(
            Graph::mock(reqwest::Url::parse(&origin).unwrap()),
            "bootstrap".into(),
            address,
            state,
        );
        app.docs.lock().await.insert(
            "doc".into(),
            Document {
                id: "00000000-0000-0000-0000-000000000001".into(),
                drive: "drive".into(),
                item: "item".into(),
                name: "test.docx".into(),
                etag: "old".into(),
                save_revision: Uuid::new_v4(),
                capability: "cap".into(),
                expires: Instant::now() + SESSION_LIFETIME,
                recoveries: Vec::new(),
                session_lease: Arc::new(()),
            },
        );
        (app, mock, task)
    }

    #[tokio::test]
    async fn creates_each_office_type_in_the_selected_folder_and_opens_it() {
        for (kind, extension, bytes, drive, parent, base) in [
            (
                "word",
                "docx",
                include_bytes!("../assets/blank.docx").as_slice(),
                "drive",
                "root",
                "Draft & notes",
            ),
            (
                "excel",
                "xlsx",
                include_bytes!("../assets/blank.xlsx").as_slice(),
                "share-drive",
                "folder",
                "Draft",
            ),
            (
                "powerpoint",
                "pptx",
                include_bytes!("../assets/blank.pptx").as_slice(),
                "share-drive",
                "folder",
                "Draft",
            ),
        ] {
            let name = format!("{base}.{extension}");
            let (app, mock, task) = create_mock_app(drive, parent, &name, bytes, false).await;
            let form = HashMap::from([
                ("k".into(), "bootstrap".into()),
                ("op".into(), "create".into()),
                ("type".into(), kind.into()),
                ("name".into(), base.into()),
                ("drive".into(), drive.into()),
                ("parent".into(), parent.into()),
            ]);
            let response = action(State(app), Form(form)).await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(
                response
                    .headers()
                    .get(header::LOCATION)
                    .unwrap()
                    .to_str()
                    .unwrap(),
                format!("/open?k=bootstrap&drive={drive}&item=created")
            );
            assert_eq!(mock.sessions.load(Ordering::SeqCst), 1);
            assert_eq!(mock.uploads.load(Ordering::SeqCst), 1);
            task.abort();
        }
    }

    #[tokio::test]
    async fn creation_rejects_bad_requests_and_preserves_existing_files() {
        let (app, mock, task) = create_mock_app(
            "drive",
            "root",
            "Draft.docx",
            include_bytes!("../assets/blank.docx"),
            true,
        )
        .await;
        let mut form = HashMap::from([
            ("k".into(), "wrong".into()),
            ("op".into(), "create".into()),
            ("type".into(), "word".into()),
            ("name".into(), "Draft".into()),
            ("drive".into(), "drive".into()),
            ("parent".into(), "root".into()),
        ]);
        assert_eq!(
            action(State(app.clone()), Form(form.clone()))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        form.insert("k".into(), "bootstrap".into());
        for (key, value) in [("type", "unknown"), ("name", "../Draft"), ("name", "  ")] {
            let mut invalid = form.clone();
            invalid.insert(key.into(), value.into());
            assert_eq!(
                action(State(app.clone()), Form(invalid)).await.status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(mock.sessions.load(Ordering::SeqCst), 0);
        let response = action(State(app), Form(form)).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(mock.sessions.load(Ordering::SeqCst), 1);
        assert_eq!(mock.uploads.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn new_document_action_appears_only_while_browsing_folders() {
        let (app, _, task) = mock_app(3).await;
        let folder = HashMap::from([
            ("view".into(), "folder".into()),
            ("drive".into(), "drive".into()),
            ("parent".into(), "root".into()),
            ("site".into(), "site-id".into()),
        ]);
        let html = render_picker_view(&app, &folder, false).await.unwrap();
        assert!(html.contains("<summary>New document</summary>"));
        assert!(html.contains("name='drive' value='drive'"));
        assert!(html.contains("name='parent' value='root'"));
        assert!(html.contains("name='site' value='site-id'"));
        let shared = HashMap::from([("view".into(), "shared".into())]);
        let html = render_picker_view(&app, &shared, false).await.unwrap();
        assert!(!html.contains("<summary>New document</summary>"));
        task.abort();
    }

    async fn save(app: &App) -> Response {
        let token = app.issue("doc".into(), Kind::Upload).await;
        put(
            State(app.clone()),
            Query(HashMap::from([("token".into(), token)])),
            Request::new(axum::body::Body::from("edits")),
        )
        .await
    }

    async fn fetch_document(app: &App) -> Response {
        let token = app.issue("doc".into(), Kind::Fetch).await;
        fetch(
            State(app.clone()),
            Query(HashMap::from([("token".into(), token)])),
        )
        .await
    }

    fn assert_transfer_cors(response: &Response) {
        assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn busy_transfers_preserve_one_shot_urls_for_retry() {
        let (mut app, mock, task) = mock_app(3).await;
        app.downloads = Arc::new(Semaphore::new(1));
        let busy = app.downloads.clone().try_acquire_owned().unwrap();
        let token = app.issue("doc".into(), Kind::Fetch).await;
        let q = HashMap::from([("token".into(), token.clone())]);
        let response = fetch(State(app.clone()), Query(q.clone())).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_transfer_cors(&response);
        assert!(app.one_shots.lock().await.contains_key(&token));
        assert_eq!(mock.downloads.load(Ordering::SeqCst), 0);
        let invalid = fetch(
            State(app.clone()),
            Query(HashMap::from([("token".into(), "invalid".into())])),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        assert_transfer_cors(&invalid);
        drop(busy);
        let response = fetch(State(app.clone()), Query(q.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!app.one_shots.lock().await.contains_key(&token));
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            fetch(State(app.clone()), Query(q)).await.status(),
            StatusCode::UNAUTHORIZED
        );

        let busy = app.uploads.clone().try_acquire_owned().unwrap();
        let token = app.issue("doc".into(), Kind::Upload).await;
        let q = HashMap::from([("token".into(), token.clone())]);
        let response = put(
            State(app.clone()),
            Query(q.clone()),
            Request::new(axum::body::Body::from("edits")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_transfer_cors(&response);
        assert!(app.one_shots.lock().await.contains_key(&token));
        assert_eq!(mock.sessions.load(Ordering::SeqCst), 0);
        drop(busy);
        let response = put(
            State(app.clone()),
            Query(q.clone()),
            Request::new(axum::body::Body::from("edits")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!app.one_shots.lock().await.contains_key(&token));
        assert_eq!(mock.sessions.load(Ordering::SeqCst), 1);
        let response = put(
            State(app.clone()),
            Query(q),
            Request::new(axum::body::Body::from("edits")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_transfer_cors(&response);
        task.abort();
    }

    #[tokio::test]
    async fn delayed_upload_urls_cannot_inherit_a_newer_save_revision() {
        let (app, mock, task) = mock_app(3).await;
        let delayed = app.issue("doc".into(), Kind::Upload).await;
        let fetch_token = app.issue("doc".into(), Kind::Fetch).await;
        let initial_revision = app.docs.lock().await.get("doc").unwrap().save_revision;
        // A busy response must preserve the URL, but not grant it a future revision.
        let busy = app.uploads.clone().try_acquire_owned().unwrap();
        assert!(matches!(
            app.consume(&delayed, Kind::Upload).await,
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));
        drop(busy);
        assert_eq!(save(&app).await.status(), StatusCode::OK);
        assert_ne!(
            app.docs.lock().await.get("doc").unwrap().save_revision,
            initial_revision
        );
        // A pending body proves rejection happens before buffering stale bytes.
        let body = axum::body::Body::from_stream(futures_util::stream::pending::<
            Result<Bytes, std::io::Error>,
        >());
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            put(
                State(app.clone()),
                Query(HashMap::from([("token".into(), delayed.clone())])),
                Request::new(body),
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_transfer_cors(&response);
        assert!(!app.one_shots.lock().await.contains_key(&delayed));
        assert_eq!(mock.sessions.load(Ordering::SeqCst), 1);
        assert_eq!(mock.uploads.load(Ordering::SeqCst), 1);
        assert_eq!(app.uploads.available_permits(), 1);
        // Downloads are still valid, and newly issued saves use the new revision.
        drop(app.consume(&fetch_token, Kind::Fetch).await.unwrap());
        let fresh = app.issue("doc".into(), Kind::Upload).await;
        let (doc, permit) = app.consume(&fresh, Kind::Upload).await.unwrap();
        assert_eq!(doc.etag, "saved");
        assert_ne!(doc.save_revision, initial_revision);
        drop(permit);
        task.abort();
    }

    #[tokio::test]
    async fn successful_save_without_etag_still_invalidates_older_uploads() {
        let (app, mock, task) = mock_app(6).await;
        let delayed = app.issue("doc".into(), Kind::Upload).await;
        assert_eq!(save(&app).await.status(), StatusCode::OK);
        assert_eq!(app.docs.lock().await.get("doc").unwrap().etag, "old");
        assert!(matches!(
            app.consume(&delayed, Kind::Upload).await,
            Err(StatusCode::CONFLICT)
        ));
        assert_eq!(mock.uploads.load(Ordering::SeqCst), 1);
        assert_eq!(app.uploads.available_permits(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn transfer_error_responses_include_cors_and_no_store() {
        let (app, _, task) = mock_app(5).await;
        for q in [
            HashMap::new(),
            HashMap::from([("token".into(), "invalid".into())]),
        ] {
            let response = fetch(State(app.clone()), Query(q.clone())).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_transfer_cors(&response);
            let response = put(
                State(app.clone()),
                Query(q),
                Request::new(axum::body::Body::empty()),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_transfer_cors(&response);
        }
        let response = fetch_document(&app).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_transfer_cors(&response);

        // Direct handler invocation uses the extractor's default 2 MiB limit;
        // exercise its rejection without allocating a 250 MB document.
        let token = app.issue("doc".into(), Kind::Upload).await;
        let response = put(
            State(app.clone()),
            Query(HashMap::from([("token".into(), token)])),
            Request::new(axum::body::Body::from(vec![0; 2 * 1024 * 1024 + 1])),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_transfer_cors(&response);
        task.abort();
    }

    #[tokio::test]
    async fn download_admission_lasts_until_body_completion_or_drop() {
        let (mut app, mock, task) = mock_app(3).await;
        app.downloads = Arc::new(Semaphore::new(1));
        let response = fetch_document(&app).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(app.downloads.available_permits(), 0);
        assert_eq!(mock.downloads.load(Ordering::SeqCst), 1);

        assert_eq!(
            fetch_document(&app).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(mock.downloads.load(Ordering::SeqCst), 1);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"document");
        assert_eq!(app.downloads.available_permits(), 1);

        let response = fetch_document(&app).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(app.downloads.available_permits(), 0);
        drop(response);
        assert_eq!(app.downloads.available_permits(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn download_headers_do_not_wait_for_the_upstream_body() {
        let (app, _, task) = mock_app(4).await;
        let permits = app.downloads.available_permits();
        let response = tokio::time::timeout(Duration::from_secs(2), fetch_document(&app))
            .await
            .expect("Download buffered the upstream body before responding");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(app.downloads.available_permits(), permits - 1);
        let mut body = response.into_body().into_data_stream();
        assert!(tokio::time::timeout(Duration::from_millis(50), body.next())
            .await
            .is_err());
        assert_eq!(app.downloads.available_permits(), permits - 1);
        drop(body);
        assert_eq!(app.downloads.available_permits(), permits);
        task.abort();
    }

    #[tokio::test]
    async fn failed_download_releases_its_admission_permit() {
        let (app, _, task) = mock_app(5).await;
        let permits = app.downloads.available_permits();
        assert_eq!(fetch_document(&app).await.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(app.downloads.available_permits(), permits);
        task.abort();
    }

    #[tokio::test]
    async fn graph_conflicts_and_upload_failures_preserve_edited_bytes() {
        for mode in 0..3 {
            let (app, mock, task) = mock_app(mode).await;
            let response = save(&app).await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let body = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            let path = value["recoveryPath"].as_str().unwrap();
            assert_eq!(tokio::fs::read(path).await.unwrap(), b"edits");
            assert_eq!(mock.sessions.load(Ordering::SeqCst), usize::from(mode != 0));
            assert_eq!(mock.uploads.load(Ordering::SeqCst), usize::from(mode == 2));
            task.abort();
            tokio::fs::remove_dir_all(&app.state).await.unwrap();
        }
    }

    #[tokio::test]
    async fn recovery_failure_does_not_claim_preservation() {
        let (app, _, task) = mock_app(0).await;
        tokio::fs::write(&app.state, b"not a directory")
            .await
            .unwrap();
        let response = save(&app).await;
        assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert!(value.get("recoveryPath").is_none());
        assert!(value["error"]
            .as_str()
            .unwrap()
            .contains("Keep the document open"));
        tokio::fs::remove_file(&app.state).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn recovery_quota_preserves_existing_copy_and_success_cleans_retry() {
        let (app, _, task) = mock_app(3).await;
        let doc = app.docs.lock().await.get("doc").unwrap().clone();
        let other = Document {
            id: "00000000-0000-0000-0000-000000000002".into(),
            ..doc.clone()
        };
        let path = app.recovery_with_limit(&doc, b"edits", 5).await.unwrap();
        assert!(app.recovery_with_limit(&other, b"more", 5).await.is_err());
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"edits");
        let replacement = app.recovery_with_limit(&doc, b"fresh", 5).await.unwrap();
        assert_eq!(replacement, path);
        let mut entries = tokio::fs::read_dir(&app.state).await.unwrap();
        let mut count = 0;
        while let Some(entry) = entries.next_entry().await.unwrap() {
            assert!(entry.path() == path || entry.path() == path.with_extension("json"));
            count += 1;
        }
        assert_eq!(count, 2);
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"fresh");
        assert!(app
            .recovery_with_limit(&doc, b"too large", 5)
            .await
            .is_err());
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"fresh");
        app.docs
            .lock()
            .await
            .get_mut("doc")
            .unwrap()
            .recoveries
            .push(path.clone());
        assert_eq!(save(&app).await.status(), StatusCode::OK);
        assert!(!path.exists());
        assert!(!path.with_extension("json").exists());
        assert_eq!(app.docs.lock().await.get("doc").unwrap().etag, "saved");
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn recovery_quota_counts_only_final_recovery_files() {
        let (app, _, task) = mock_app(3).await;
        let doc = app.docs.lock().await.get("doc").unwrap().clone();
        let other = Document {
            id: "00000000-0000-0000-0000-000000000002".into(),
            ..doc.clone()
        };
        tokio::fs::create_dir_all(&app.state).await.unwrap();
        // Simulate repeated crashes, including interrupted metadata writes.
        // These files must be reclaimed before another recovery is written.
        let mut leftovers = Vec::new();
        for _ in 0..32 {
            let temporary = app.state.join(format!(
                ".recovery-{}-{}.tmp",
                Uuid::new_v4(),
                Uuid::new_v4()
            ));
            let metadata_temporary = temporary.with_extension("json.tmp");
            tokio::fs::write(&temporary, b"interrupted").await.unwrap();
            tokio::fs::write(&metadata_temporary, b"interrupted metadata")
                .await
                .unwrap();
            leftovers.extend([temporary, metadata_temporary]);
            let sidecar = app.state.join(format!("recovery-{}.json", Uuid::new_v4()));
            tokio::fs::write(sidecar, b"metadata").await.unwrap();
        }
        tokio::fs::write(app.state.join("recovery-not-a-uuid.bin"), b"unrelated")
            .await
            .unwrap();
        let path = app.recovery_with_limit(&doc, b"edits", 5).await.unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"edits");
        assert!(leftovers.iter().all(|path| !path.exists()));
        // Genuine completed copies still enforce both limits.
        assert!(app.recovery_with_limit(&other, b"more", 5).await.is_err());
        for _ in 0..31 {
            let name = format!("recovery-{}.bin", Uuid::new_v4());
            tokio::fs::write(app.state.join(name), b"").await.unwrap();
        }
        assert!(app.recovery_with_limit(&other, b"more", 100).await.is_err());
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        task.abort();
    }

    #[test]
    fn recovery_temporary_names_require_exact_generated_uuid_format() {
        let doc = "00000000-0000-0000-0000-000000000001";
        let nonce = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        for suffix in ["tmp", "json.tmp"] {
            assert!(recovery_temporary_name(&format!(
                ".recovery-{doc}-{nonce}.{suffix}"
            )));
        }
        for name in [
            format!("recovery-{doc}-{nonce}.tmp"),
            format!(".recovery-{doc}-{nonce}.json"),
            format!(".recovery-{doc}-{nonce}.tmp.extra"),
            format!(".recovery-{doc}-{}.tmp", nonce.to_uppercase()),
            format!(".recovery-{doc}-{}.tmp", nonce.replace('-', "")),
            format!(".recovery-{doc}-not-a-uuid.tmp"),
            format!(".recovery-{doc}-{nonce}-extra.tmp"),
            format!("../.recovery-{doc}-{nonce}.tmp"),
            format!(".recovery-{}é{}.tmp", "a".repeat(35), "b".repeat(36)),
            format!(".recovery-💾-{nonce}.tmp"),
        ] {
            assert!(!recovery_temporary_name(&name), "{name}");
        }
    }

    #[tokio::test]
    async fn recovery_cleanup_preserves_unrelated_files_and_symlinks() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;

        let (app, _, task) = mock_app(3).await;
        let doc = app.docs.lock().await.get("doc").unwrap().clone();
        let path = app.recovery(&doc, b"edits").await.unwrap();
        let malformed = app.state.join(".recovery-not-a-session-or-nonce.tmp");
        tokio::fs::write(&malformed, b"unrelated").await.unwrap();
        let non_utf8 = app
            .state
            .join(OsString::from_vec(b".recovery-\xff.tmp".to_vec()));
        tokio::fs::write(&non_utf8, b"unrelated non-UTF-8")
            .await
            .unwrap();
        let target = app.state.join("unrelated.txt");
        tokio::fs::write(&target, b"keep target").await.unwrap();
        let mut links = Vec::new();
        for suffix in ["tmp", "json.tmp"] {
            let link = app
                .state
                .join(format!(".recovery-{}-{}.{suffix}", doc.id, Uuid::new_v4()));
            symlink(&target, &link).unwrap();
            links.push(link);
        }
        let directory = app
            .state
            .join(format!(".recovery-{}-{}.tmp", doc.id, Uuid::new_v4()));
        tokio::fs::create_dir(&directory).await.unwrap();
        let orphan = app
            .state
            .join(format!(".recovery-{}-{}.tmp", doc.id, Uuid::new_v4()));
        tokio::fs::write(&orphan, b"interrupted").await.unwrap();
        // Even when quota rejects the new save, cleanup must leave complete
        // copies and unrelated filesystem entries untouched.
        assert!(app
            .recovery_with_limit(&doc, b"too large", 5)
            .await
            .is_err());
        assert!(!orphan.exists());
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"edits");
        assert_eq!(recovery_metadata(&path).await.unwrap().name, doc.name);
        assert_eq!(tokio::fs::read(&malformed).await.unwrap(), b"unrelated");
        assert_eq!(
            tokio::fs::read(&non_utf8).await.unwrap(),
            b"unrelated non-UTF-8"
        );
        assert_eq!(tokio::fs::read(&target).await.unwrap(), b"keep target");
        assert!(directory.is_dir());
        for link in links {
            assert!(tokio::fs::symlink_metadata(link)
                .await
                .unwrap()
                .file_type()
                .is_symlink());
        }
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn recovery_downloads_stream_under_shared_admission() {
        let (mut app, mock, task) = mock_app(3).await;
        app.downloads = Arc::new(Semaphore::new(1));
        let doc = app.docs.lock().await.get("doc").unwrap().clone();
        let bytes = vec![b'x'; 128 * 1024 + 5];
        let path = app.recovery(&doc, &bytes).await.unwrap();
        let q = HashMap::from([
            ("k".into(), "bootstrap".into()),
            (
                "name".into(),
                path.file_name().unwrap().to_str().unwrap().to_owned(),
            ),
        ]);
        let response = recovery_download(State(app.clone()), Query(q.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(app.downloads.available_permits(), 0);
        assert!(app.recovery_lock.try_lock().is_ok());
        assert_eq!(
            recovery_download(State(app.clone()), Query(q.clone()))
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            fetch_document(&app).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(mock.downloads.load(Ordering::SeqCst), 0);
        let mut stream = response.into_body().into_data_stream();
        let first = stream.next().await.unwrap().unwrap();
        assert!(!first.is_empty());
        assert!(first.len() <= 64 * 1024);
        assert_eq!(app.downloads.available_permits(), 0);
        drop(stream);
        assert_eq!(app.downloads.available_permits(), 1);

        let response = recovery_download(State(app.clone()), Query(q.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let downloaded = axum::body::to_bytes(response.into_body(), bytes.len())
            .await
            .unwrap();
        assert_eq!(&downloaded[..], bytes.as_slice());
        assert_eq!(app.downloads.available_permits(), 1);

        let response = recovery_download(State(app.clone()), Query(q.clone())).await;
        assert_eq!(app.downloads.available_permits(), 0);
        drop(response);
        assert_eq!(app.downloads.available_permits(), 1);

        app.remove_recovery(&path).await.unwrap();
        assert_eq!(
            recovery_download(State(app.clone()), Query(q))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(app.downloads.available_permits(), 1);
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn recovery_metadata_survives_restart_and_names_downloads() {
        use std::os::unix::fs::PermissionsExt;

        let (app, _, task) = mock_app(3).await;
        let mut doc = app.docs.lock().await.get("doc").unwrap().clone();
        doc.name = "Résumé & notes.docx".into();
        let path = app.recovery(&doc, b"edits").await.unwrap();
        let metadata = recovery_metadata(&path).await.unwrap();
        assert_eq!(metadata.name, doc.name);
        assert_eq!(metadata.drive, doc.drive);
        assert_eq!(metadata.item, doc.item);
        assert_eq!(
            tokio::fs::metadata(path.with_extension("json"))
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let restarted = App::new(
            app.graph.clone(),
            app.bootstrap.clone(),
            app.address,
            app.state.clone(),
        );
        assert!(restarted.docs.lock().await.is_empty());
        let q = HashMap::from([
            ("k".into(), "bootstrap".into()),
            (
                "name".into(),
                path.file_name().unwrap().to_str().unwrap().to_owned(),
            ),
        ]);
        let response = recovery_picker(State(restarted.clone()), Query(q.clone())).await;
        let html = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let html = String::from_utf8(html.to_vec()).unwrap();
        assert!(html.contains(">Résumé &amp; notes.docx</a>"));
        assert!(!html.contains(".json"));
        let response = recovery_download(State(restarted), Query(q)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"R_sum_ _ notes.docx\"; filename*=UTF-8''R%C3%A9sum%C3%A9%20%26%20notes.docx"
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap(),
            &b"edits"[..]
        );
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn recovery_download_sanitizes_untrusted_filenames() {
        let (app, _, task) = mock_app(3).await;
        let mut doc = app.docs.lock().await.get("doc").unwrap().clone();
        doc.name = "../../folder\\Résumé \"<draft>\"\r\n.docx".into();
        let path = app.recovery(&doc, b"edits").await.unwrap();
        let q = HashMap::from([
            ("k".into(), "bootstrap".into()),
            (
                "name".into(),
                path.file_name().unwrap().to_str().unwrap().to_owned(),
            ),
        ]);
        let response = recovery_picker(State(app.clone()), Query(q.clone())).await;
        let html = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let html = String::from_utf8(html.to_vec()).unwrap();
        assert!(html.contains("&quot;&lt;draft&gt;&quot;"));
        assert!(!html.contains("<draft>"));
        let response = recovery_download(State(app.clone()), Query(q)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"R_sum_ __draft____.docx\"; filename*=UTF-8''R%C3%A9sum%C3%A9%20__draft____.docx"
        );
        assert_eq!(recovery_filename("../.."), "recovered-document.bin");
        assert_eq!(recovery_filename("folder/"), "recovered-document.bin");
        assert_eq!(recovery_filename("notes\u{202e}.docx"), "notes_.docx");
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn recovery_legacy_copies_remain_downloadable() {
        let (app, _, task) = mock_app(3).await;
        tokio::fs::create_dir_all(&app.state).await.unwrap();
        let name = "recovery-00000000-0000-0000-0000-000000000001.bin";
        let path = app.state.join(name);
        tokio::fs::write(&path, b"legacy edits").await.unwrap();
        let mut q = HashMap::from([
            ("k".into(), "bootstrap".into()),
            ("name".into(), name.into()),
        ]);
        for invalid_metadata in [false, true] {
            if invalid_metadata {
                tokio::fs::write(path.with_extension("json"), b"{invalid json")
                    .await
                    .unwrap();
            }
            let response = recovery_picker(State(app.clone()), Query(q.clone())).await;
            let html = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap();
            let html = String::from_utf8(html.to_vec()).unwrap();
            assert!(html.contains(&format!(">{name}</a>")));
            let response = recovery_download(State(app.clone()), Query(q.clone())).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(response.headers()[header::CONTENT_DISPOSITION]
                .to_str()
                .unwrap()
                .contains(name));
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 8192)
                    .await
                    .unwrap(),
                &b"legacy edits"[..]
            );
        }
        q.insert("confirm".into(), "yes".into());
        assert_eq!(
            recovery_remove(State(app.clone()), Form(q)).await.status(),
            StatusCode::SEE_OTHER
        );
        assert!(!path.exists());
        assert!(!path.with_extension("json").exists());
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn recovery_metadata_failure_preserves_existing_bytes() {
        let (app, _, task) = mock_app(3).await;
        let doc = app.docs.lock().await.get("doc").unwrap().clone();
        let path = app.recovery(&doc, b"old edits").await.unwrap();
        let metadata = path.with_extension("json");
        tokio::fs::remove_file(&metadata).await.unwrap();
        // A directory at the sidecar destination forces its atomic rename to
        // fail, after both temporary files have been written successfully.
        tokio::fs::create_dir(&metadata).await.unwrap();
        assert!(app.recovery(&doc, b"new edits").await.is_err());
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"old edits");
        let mut entries = tokio::fs::read_dir(&app.state).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            assert!(entry.path() == path || entry.path() == metadata);
        }
        // A first save with the same failure must not publish anonymous bytes.
        tokio::fs::remove_file(&path).await.unwrap();
        assert!(app.recovery(&doc, b"new edits").await.is_err());
        assert!(!path.exists());
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn recovery_removal_cleans_orphaned_metadata() {
        let (app, _, task) = mock_app(3).await;
        let doc = app.docs.lock().await.get("doc").unwrap().clone();
        let path = app.recovery(&doc, b"edits").await.unwrap();
        tokio::fs::remove_file(&path).await.unwrap();
        assert_eq!(
            app.remove_recovery(&path).await.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(!path.with_extension("json").exists());
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn document_body_limit_is_local_to_authenticated_uploads() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (app, _, graph_task) = mock_app(0).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = app.clone().router();
        let bridge = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let client = reqwest::Client::new();
        let body = "x".repeat(2 * 1024 * 1024 + 1);
        for path in ["/action", "/recovery/remove"] {
            let response = client
                .post(format!("http://{address}{path}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }
        // Send only headers: unauthorized uploads must be rejected before the
        // server waits for or buffers any document bytes.
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(format!("POST /co/collab/put?token=wrong HTTP/1.1\r\nHost: {address}\r\nContent-Length: {MAX_DOCUMENT}\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = [0; 512];
        let size = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(&response[..size])
            .unwrap()
            .starts_with("HTTP/1.1 401"));
        let token = app.issue("doc".into(), Kind::Upload).await;
        let response = client
            .post(format!("http://{address}/co/collab/put?token={token}"))
            .body(body.clone())
            .send()
            .await
            .unwrap();
        // A document above the form limit reaches save/recovery unchanged.
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let result: Value = response.json().await.unwrap();
        assert_eq!(
            tokio::fs::read(result["recoveryPath"].as_str().unwrap())
                .await
                .unwrap(),
            body.as_bytes()
        );
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        bridge.abort();
        graph_task.abort();
    }

    #[tokio::test]
    async fn upload_admission_precedes_buffering_and_releases_on_disconnect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (app, mock, graph_task) = mock_app(3).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = app.clone().router();
        let bridge = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let first = app.issue("doc".into(), Kind::Upload).await;
        let mut stalled = tokio::net::TcpStream::connect(address).await.unwrap();
        stalled
            .write_all(format!("POST /co/collab/put?token={first} HTTP/1.1\r\nHost: {address}\r\nContent-Length: 5\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.uploads.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let second = app.issue("doc".into(), Kind::Upload).await;
        let mut rejected = tokio::net::TcpStream::connect(address).await.unwrap();
        rejected
            .write_all(format!("POST /co/collab/put?token={second} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {MAX_DOCUMENT}\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = [0; 512];
        let size = tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(&response[..size])
            .unwrap()
            .starts_with("HTTP/1.1 503"));
        assert_eq!(mock.sessions.load(Ordering::SeqCst), 0);
        drop(stalled);
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.uploads.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(save(&app).await.status(), StatusCode::OK);
        assert_eq!(app.uploads.available_permits(), 1);
        bridge.abort();
        graph_task.abort();
    }

    #[tokio::test]
    async fn stalled_upload_times_out_and_releases_admission() {
        let (mut app, mock, graph_task) = mock_app(3).await;
        app.upload_body_timeout = Duration::from_millis(20);
        let token = app.issue("doc".into(), Kind::Upload).await;
        let body = axum::body::Body::from_stream(futures_util::stream::pending::<
            Result<Bytes, std::io::Error>,
        >());
        let response = put(
            State(app.clone()),
            Query(HashMap::from([("token".into(), token)])),
            Request::new(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_transfer_cors(&response);
        assert_eq!(app.uploads.available_permits(), 1);
        assert_eq!(mock.sessions.load(Ordering::SeqCst), 0);
        assert_eq!(save(&app).await.status(), StatusCode::OK);
        graph_task.abort();
    }

    #[tokio::test]
    async fn default_picker_keeps_navigation_without_personal_onedrive() {
        let (app, _, task) = mock_app(3).await;
        // The registered provider opens the default view with no drive ID;
        // this mock deliberately returns 404 for /me/drive.
        let html = render_picker(&app, &HashMap::new()).await.unwrap();
        assert!(html.contains("Microsoft 365 unavailable"));
        assert!(html.contains("href='/?k=bootstrap&amp;view=sites'"));
        assert!(html.contains("href='/recovery?k=bootstrap'"));
        assert!(html.contains(&sharing_link_form("bootstrap")));
        let sites = HashMap::from([("view".into(), "sites".into())]);
        let html = render_picker(&app, &sites).await.unwrap();
        assert!(html.contains("Find a SharePoint site"));
        assert!(!location_navigation("bootstrap", "", false).contains("view=sites"));
        task.abort();
    }

    #[tokio::test]
    async fn file_only_picker_keeps_working_share_form_without_personal_onedrive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .route(
                "/me/drive",
                get(|| async {
                    (
                        StatusCode::NOT_FOUND,
                        axum::Json(json!({"error":{"code":"noOneDrive"}})),
                    )
                }),
            )
            .route(
                "/shares/{share}/driveItem",
                get(|headers: HeaderMap| async move {
                    let authorization = headers.get(header::AUTHORIZATION).unwrap();
                    assert_eq!(authorization, "Bearer mock-token");
                    assert_eq!(headers.get("Prefer").unwrap(), "redeemSharingLink");
                    axum::Json(json!({
                        "id":"shared-file", "name":"Shared.docx", "file":{},
                        "eTag":"shared-etag", "parentReference":{"driveId":"shared-drive"}
                    }))
                }),
            );
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let app = App::new(
            Graph::mock(reqwest::Url::parse(&format!("http://{address}")).unwrap()),
            "bootstrap'<&".into(),
            address,
            std::env::temp_dir().join(format!("collabora-share-{}", Uuid::new_v4())),
        );
        // Files.ReadWrite permits share resolution but not site discovery.
        let html = render_picker_with_consent(&app, &HashMap::new(), false)
            .await
            .unwrap();
        assert!(html.contains("noOneDrive"));
        assert!(!html.contains("view=sites"));
        assert!(html.contains("<form action='/open' method='get'>"));
        assert!(html.contains("name='k' value='bootstrap&#39;&lt;&amp;'"));
        assert!(html.contains("id='share-url' name='share' type='url'"));
        let share_link = "https://example.sharepoint.com/shared-file";
        let response = open(
            State(app.clone()),
            Query(HashMap::from([
                ("k".into(), app.bootstrap.clone()),
                ("share".into(), share_link.into()),
            ])),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let docs = app.docs.lock().await;
        assert_eq!(docs.len(), 1);
        let doc = docs.values().next().unwrap();
        assert_eq!(doc.drive, "shared-drive");
        assert_eq!(doc.item, "shared-file");
        task.abort();
    }

    #[tokio::test]
    async fn sharepoint_library_does_not_require_personal_drive() {
        let (app, _, task) = mock_app(3).await;
        let q = HashMap::from([
            ("view".into(), "folder".into()),
            ("drive".into(), "drive".into()),
        ]);
        // Mock deliberately has no /me/drive route.
        let html = render_picker(&app, &q).await.unwrap();
        assert!(html.contains("This folder is empty"));
        assert!(!html.contains("Microsoft 365 unavailable"));
        assert!(html.contains(&sharing_link_form("bootstrap")));
        task.abort();
    }
    #[tokio::test]
    async fn websocket_authentication_protocol_and_one_shot_tokens() {
        use futures_util::SinkExt;
        use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
        let (app, _, graph_task) = mock_app(3).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = app.clone().router();
        let bridge = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let doc_id = "00000000-0000-0000-0000-000000000001";
        let doc = app.docs.lock().await.remove("doc").unwrap();
        app.docs.lock().await.insert(doc_id.into(), doc);
        let url = format!("ws://{address}/co/collab?WOPISrc=http://localhost/wopi/{doc_id}");
        let (mut bad, _) = connect_async(&url).await.unwrap();
        bad.send(ClientMessage::Text("access_token wrong".into()))
            .await
            .unwrap();
        assert!(bad
            .next()
            .await
            .unwrap()
            .unwrap()
            .to_text()
            .unwrap()
            .contains("accesstoken"));
        assert!(app.one_shots.lock().await.is_empty());

        let (mut ws, _) = connect_async(&url).await.unwrap();
        ws.send(ClientMessage::Text("access_token cap".into()))
            .await
            .unwrap();
        let authenticated: Value =
            serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(authenticated["type"], "authenticated");
        ws.next().await.unwrap().unwrap(); // empty user list
                                           // An idle editor still owns a lease. Opening a second document must
                                           // not prune the first session after its nominal two-hour expiry.
        app.docs.lock().await.get_mut(doc_id).unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        let opened = open(
            State(app.clone()),
            Query(HashMap::from([
                ("k".into(), "bootstrap".into()),
                ("drive".into(), "drive".into()),
                ("item".into(), "item".into()),
            ])),
        )
        .await;
        assert_eq!(opened.status(), StatusCode::SEE_OTHER);
        assert!(app.docs.lock().await.contains_key(doc_id));
        ws.send(ClientMessage::Text(
            r#"{"type":"fetch","stream":"contents","requestId":"wasm-init"}"#.into(),
        ))
        .await
        .unwrap();
        let reply: Value =
            serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(reply["type"], "fetch_url");
        assert_eq!(reply["requestId"], "wasm-init");
        let token = reply["url"]
            .as_str()
            .unwrap()
            .split("token=")
            .nth(1)
            .unwrap();
        assert!(app.consume(token, Kind::Fetch).await.is_ok());
        assert!(app.consume(token, Kind::Fetch).await.is_err());
        ws.send(ClientMessage::Text(
            r#"{"type":"upload","stream":"contents","requestId":"save-after-idle"}"#.into(),
        ))
        .await
        .unwrap();
        let reply: Value =
            serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(reply["type"], "upload_url");
        let token = reply["url"]
            .as_str()
            .unwrap()
            .split("token=")
            .nth(1)
            .unwrap();
        let saved = put(
            State(app.clone()),
            Query(HashMap::from([("token".into(), token.into())])),
            Request::new(axum::body::Body::from("edits")),
        )
        .await;
        assert_eq!(saved.status(), StatusCode::OK);
        let wrong_kind = app.issue(doc_id.into(), Kind::Fetch).await;
        assert!(app.consume(&wrong_kind, Kind::Upload).await.is_err());
        let expired = app.issue(doc_id.into(), Kind::Upload).await;
        app.one_shots
            .lock()
            .await
            .get_mut(&expired)
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        assert!(app.consume(&expired, Kind::Upload).await.is_err());
        ws.send(ClientMessage::Text(
            r#"{"type":"unknown-version-message"}"#.into(),
        ))
        .await
        .unwrap();
        let reply: Value =
            serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(reply["type"], "error");
        assert!(reply["error"]
            .as_str()
            .unwrap()
            .contains("Unsupported Collabora protocol"));
        bridge.abort();
        graph_task.abort();
    }

    #[tokio::test]
    async fn websocket_rejects_binary_messages_but_keeps_control_frames() {
        use futures_util::SinkExt;
        use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};

        let (app, _, graph_task) = mock_app(3).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = app.clone().router();
        let bridge = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let doc_id = "00000000-0000-0000-0000-000000000001";
        let doc = app.docs.lock().await.remove("doc").unwrap();
        app.docs.lock().await.insert(doc_id.into(), doc);
        let url = format!("ws://{address}/co/collab?WOPISrc=http://localhost/wopi/{doc_id}");
        let (mut ws, _) = connect_async(&url).await.unwrap();
        ws.send(ClientMessage::Text("access_token cap".into()))
            .await
            .unwrap();
        ws.next().await.unwrap().unwrap();
        ws.next().await.unwrap().unwrap();
        ws.send(ClientMessage::Ping(b"health".to_vec().into()))
            .await
            .unwrap();
        let pong = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(pong, ClientMessage::Pong(payload) if &payload[..] == b"health"));
        ws.send(ClientMessage::Pong(b"ack".to_vec().into()))
            .await
            .unwrap();
        ws.send(ClientMessage::Text(
            r#"{"type":"fetch","stream":"contents"}"#.into(),
        ))
        .await
        .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let reply: Value = serde_json::from_str(reply.to_text().unwrap()).unwrap();
        assert_eq!(reply["type"], "fetch_url");
        assert_eq!(app.one_shots.lock().await.len(), 1);
        ws.send(ClientMessage::Binary(
            br#"{"type":"upload","stream":"contents"}"#.to_vec().into(),
        ))
        .await
        .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let reply: Value = serde_json::from_str(reply.to_text().unwrap()).unwrap();
        assert_eq!(reply["type"], "error");
        assert!(reply["error"].as_str().unwrap().contains("JSON text"));
        let closed = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap();
        assert!(matches!(closed, Some(Ok(ClientMessage::Close(_)))));
        assert_eq!(app.one_shots.lock().await.len(), 1);
        bridge.abort();
        graph_task.abort();
    }

    #[tokio::test]
    async fn missing_websocket_session_does_not_issue_upload_tokens() {
        use futures_util::SinkExt;
        use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};

        let (app, _, graph_task) = mock_app(3).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = app.clone().router();
        let bridge = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let doc_id = "00000000-0000-0000-0000-000000000001";
        let doc = app.docs.lock().await.remove("doc").unwrap();
        app.docs.lock().await.insert(doc_id.into(), doc);
        let url = format!("ws://{address}/co/collab?WOPISrc=http://localhost/wopi/{doc_id}");
        let (mut ws, _) = connect_async(&url).await.unwrap();
        ws.send(ClientMessage::Text("access_token cap".into()))
            .await
            .unwrap();
        ws.next().await.unwrap().unwrap();
        ws.next().await.unwrap().unwrap();
        app.docs.lock().await.remove(doc_id);
        ws.send(ClientMessage::Text(
            r#"{"type":"upload","stream":"contents","requestId":"revoked"}"#.into(),
        ))
        .await
        .unwrap();
        let reply: Value =
            serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(reply["type"], "error");
        assert!(app.one_shots.lock().await.is_empty());
        bridge.abort();
        graph_task.abort();
    }

    #[tokio::test]
    async fn unauthenticated_websockets_timeout_and_connections_are_bounded() {
        use tokio_tungstenite::connect_async;
        let (app, _, graph_task) = mock_app(3).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = app.clone().router();
        let bridge = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let url = format!("ws://{address}/co/collab?WOPISrc=http://localhost/wopi/00000000-0000-0000-0000-000000000001");
        let permit = app
            .connections
            .clone()
            .acquire_many_owned(64)
            .await
            .unwrap();
        let error = connect_async(&url).await.unwrap_err();
        match error {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE)
            }
            other => panic!("Unexpected error: {other}"),
        }
        drop(permit);
        let (mut ws, _) = connect_async(&url).await.unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(7), ws.next())
            .await
            .unwrap();
        assert!(closed.is_none() || closed.unwrap().is_err());
        bridge.abort();
        graph_task.abort();
    }
    #[tokio::test]
    async fn recovery_picker_requires_authentication_and_explicit_removal() {
        let (app, _, task) = mock_app(3).await;
        let doc = app.docs.lock().await.get("doc").unwrap().clone();
        let path = app.recovery(&doc, b"edits").await.unwrap();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let mut q = HashMap::from([("name".into(), name), ("k".into(), "wrong".into())]);
        assert_eq!(
            recovery_download(State(app.clone()), Query(q.clone()))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        q.insert("k".into(), "bootstrap".into());
        assert_eq!(
            recovery_download(State(app.clone()), Query(q.clone()))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            recovery_remove(State(app.clone()), Form(q.clone()))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(path.exists());
        q.insert("confirm".into(), "yes".into());
        assert_eq!(
            recovery_remove(State(app.clone()), Form(q)).await.status(),
            StatusCode::SEE_OTHER
        );
        assert!(!path.exists());
        assert!(!path.with_extension("json").exists());
        assert!(!recovery_name("../endpoint.json"));
        assert!(!recovery_name("recovery-../../endpoint.json.bin"));
        tokio::fs::remove_dir_all(&app.state).await.unwrap();
        task.abort();
    }

    #[test]
    fn file_rows_escape_names_and_keep_open_and_details_targets() {
        let item: Item = serde_json::from_value(json!({
            "id": "file/1", "name": "A <draft> & 'notes'.docx", "file": {},
            "size": 2048, "lastModifiedDateTime": "2026-10-13T15:17:21Z",
            "parentReference": { "driveId": "drive/1", "id": "root" }
        }))
        .unwrap();
        let html = rows(vec![item], "", "secret", &[], true).unwrap();
        assert!(html.contains("A &lt;draft&gt; &amp; &#39;notes&#39;.docx"));
        assert!(!html.contains("<draft>"));
        assert!(html.contains("/open?k=secret&amp;drive=drive%2F1&amp;item=file%2F1"));
        assert!(html.contains("/details?k=secret&amp;drive=drive%2F1&amp;item=file%2F1"));
        assert!(html.contains("2026-10-13"));
        assert!(html.contains("2.0 KB"));
    }

    #[test]
    fn folders_precede_files_and_keep_library_context() {
        let folder: Item =
            serde_json::from_value(json!({"id":"folder", "name":"Reports", "folder":{}})).unwrap();
        let file: Item =
            serde_json::from_value(json!({"id":"file", "name":"Report.pdf", "file":{}})).unwrap();
        let html = rows(
            vec![file, folder],
            "drive",
            "secret",
            &[("site", "site/1"), ("library_name", "Team docs")],
            true,
        )
        .unwrap();
        assert!(html.find("Reports").unwrap() < html.find("Report.pdf").unwrap());
        assert!(html.contains("site=site%2F1"));
        assert!(html.contains("library_name=Team%20docs"));
    }

    #[test]
    fn picker_page_loads_local_assets_under_restricted_policy() {
        let html = document_page("Microsoft 365 files", "<main>Files</main>");
        assert!(html.contains("script-src 'self'"));
        assert!(html.contains("connect-src 'self'"));
        assert!(html.contains("href='/picker.css'"));
        assert!(html.contains("src='/picker.js'"));
    }

    #[tokio::test]
    async fn picker_keeps_consent_gated_sites_and_recovery_navigation() {
        let (app, _, task) = mock_app(3).await;
        let query = HashMap::from([("drive".into(), "drive".into())]);
        let html = render_picker(&app, &query).await.unwrap();
        assert!(html.contains("SharePoint"));
        assert!(html.contains("Recovery copies"));
        assert!(html.contains("/recovery?k=bootstrap"));
        task.abort();
    }
}
