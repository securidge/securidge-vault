//! The Securidge Vault window: the main flows of DESIGN.md §8.2.
//!
//! Slow work (Argon2id unlocks, encrypting, extracting) runs on a worker
//! thread so the window stays responsive. A worker finishes by sending back
//! a closure that updates the app on the UI thread.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use vault_core::advice;
use vault_core::keyfile;
use vault_core::{vault, KdfLimits, KdfParams, KeyId, Password, UnlockedKey, Vault};
use zeroize::Zeroizing;

/// KDF settings. Production values everywhere except the test suite.
#[derive(Clone, Copy)]
pub struct Config {
    pub limits: KdfLimits,
    pub params: KdfParams,
}

impl Config {
    pub const PRODUCTION: Config = Config {
        limits: KdfLimits::PRODUCTION,
        params: KdfParams::DEFAULT,
    };
}

type Apply = Box<dyn FnOnce(&mut App) + Send>;

struct Job {
    label: String,
    started: Instant,
    rx: mpsc::Receiver<Apply>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoticeKind {
    Success,
    Error,
    Info,
}

#[derive(Clone, Debug)]
pub struct Notice {
    pub kind: NoticeKind,
    pub text: String,
}

/// Everything except the current screen, so screens can borrow both.
pub struct Runtime {
    cfg: Config,
    ctx: egui::Context,
    job: Option<Job>,
    notice: Option<Notice>,
    nav: Option<Screen>,
    /// The user was already warned that closing skips unfinished backups.
    close_warned: bool,
}

impl Runtime {
    /// Runs `work` on a worker thread; its result is applied on the UI thread.
    fn spawn(&mut self, label: &str, work: impl FnOnce() -> Apply + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            let apply = work();
            let _ = tx.send(apply);
            ctx.request_repaint();
        });
        self.notice = None;
        self.job = Some(Job {
            label: label.to_owned(),
            started: Instant::now(),
            rx,
        });
    }

    fn go(&mut self, s: Screen) {
        self.nav = Some(s);
    }
}

fn ok(app: &mut App, text: impl Into<String>) {
    app.rt.notice = Some(Notice {
        kind: NoticeKind::Success,
        text: text.into(),
    });
}

fn fail(app: &mut App, text: impl Into<String>) {
    app.rt.notice = Some(Notice {
        kind: NoticeKind::Error,
        text: text.into(),
    });
}

fn info(app: &mut App, text: impl Into<String>) {
    app.rt.notice = Some(Notice {
        kind: NoticeKind::Info,
        text: text.into(),
    });
}

pub enum Screen {
    Home,
    NewKey(NewKey),
    Backup(Backup),
    CreateVault(CreateVault),
    OpenVault(OpenVault),
    Opened(Opened),
    Passwd(Passwd),
    Verify(Verify),
    Rekey(Rekey),
}

impl Screen {
    pub fn name(&self) -> &'static str {
        match self {
            Screen::Home => "home",
            Screen::NewKey(_) => "new-key",
            Screen::Backup(_) => "backup",
            Screen::CreateVault(_) => "create-vault",
            Screen::OpenVault(_) => "open-vault",
            Screen::Opened(_) => "opened",
            Screen::Passwd(_) => "passwd",
            Screen::Verify(_) => "verify",
            Screen::Rekey(_) => "rekey",
        }
    }
}

pub struct App {
    screen: Screen,
    rt: Runtime,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, cfg: Config) -> Self {
        crate::fonts::install(&cc.egui_ctx);
        App {
            screen: Screen::Home,
            rt: Runtime {
                cfg,
                ctx: cc.egui_ctx.clone(),
                job: None,
                notice: None,
                nav: None,
                close_warned: false,
            },
        }
    }

    pub fn screen(&self) -> &Screen {
        &self.screen
    }

    pub fn screen_mut(&mut self) -> &mut Screen {
        &mut self.screen
    }

    pub fn notice(&self) -> Option<&Notice> {
        self.rt.notice.as_ref()
    }

    pub fn busy(&self) -> bool {
        self.rt.job.is_some()
    }

    /// On the backup screen with copies not yet verified.
    pub fn backup_pending(&self) -> bool {
        matches!(&self.screen, Screen::Backup(b) if !b.verified)
    }

    fn poll_job(&mut self) {
        let Some(job) = &self.rt.job else { return };
        match job.rx.try_recv() {
            Ok(apply) => {
                self.rt.job = None;
                apply(self);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.rt.job = None;
                fail(self, "The operation stopped unexpectedly.");
            }
        }
    }

    fn handle_drops(&mut self, ui: &egui::Ui) {
        let dropped: Vec<PathBuf> = ui.ctx().input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        if dropped.is_empty() || self.busy() {
            return;
        }
        match &mut self.screen {
            Screen::Home => {
                if let [one] = dropped.as_slice() {
                    if has_ext(one, vault::EXTENSION) {
                        let mut s = OpenVault::default();
                        s.vault.set(one.clone());
                        self.rt.go(Screen::OpenVault(s));
                        return;
                    }
                }
                self.rt.go(Screen::CreateVault(CreateVault {
                    inputs: dropped,
                    ..Default::default()
                }));
            }
            Screen::CreateVault(s) => {
                for p in dropped {
                    if !s.inputs.contains(&p) {
                        s.inputs.push(p);
                    }
                }
            }
            Screen::OpenVault(s) => {
                for p in dropped {
                    if has_ext(&p, keyfile::EXTENSION) {
                        s.key.set(p);
                    } else {
                        s.vault.set(p);
                    }
                }
            }
            Screen::Opened(s) => s.add(&mut self.rt, dropped),
            Screen::Rekey(s) => {
                for p in dropped {
                    s.add_vault(p);
                }
            }
            _ => {}
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_job();
        self.handle_drops(ui);

        // Closing the window mid-write is safe (the vault is replaced only
        // after the new copy is complete) but leaves a temp file behind.
        if ui.ctx().input(|i| i.viewport().close_requested()) {
            if self.busy() {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::CancelClose);
                info(self, "Please wait until the current operation finishes.");
            } else if self.backup_pending() && !self.rt.close_warned {
                // DESIGN.md §5.1: the backup step is never skipped silently.
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.rt.close_warned = true;
                fail(
                    self,
                    "Your key file has no verified backups yet. Finish the backups, or close again to quit anyway.",
                );
            }
        }

        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                // Leaving the backup flow is only possible by finishing it or
                // by explicitly accepting the risk (DESIGN.md §5.1).
                let home = !matches!(self.screen, Screen::Home) && !self.backup_pending();
                if home
                    && ui
                        .add_enabled(!self.busy(), egui::Button::new("⬅ Home"))
                        .clicked()
                {
                    self.rt.go(Screen::Home);
                }
                ui.label(RichText::new("Securidge Vault").strong().size(18.0));
                ui.label(
                    RichText::new(concat!("v", env!("CARGO_PKG_VERSION"), " · pre-alpha")).weak(),
                );
            });
            ui.add_space(4.0);
            if let Some(job) = &self.rt.job {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(format!(
                        "{}… {:.0}s",
                        job.label,
                        job.started.elapsed().as_secs_f32()
                    ));
                });
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(250));
            }
            if let Some(n) = self.rt.notice.clone() {
                let color = match n.kind {
                    NoticeKind::Success => Color32::from_rgb(46, 125, 50),
                    NoticeKind::Error => ui.visuals().error_fg_color,
                    NoticeKind::Info => ui.visuals().text_color(),
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(&n.text).color(color));
                    if ui.small_button("×").on_hover_text("Dismiss").clicked() {
                        self.rt.notice = None;
                    }
                });
            }
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            let busy = self.rt.job.is_some();
            ui.add_enabled_ui(!busy, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match &mut self.screen {
                        Screen::Home => home_ui(ui, &mut self.rt),
                        Screen::NewKey(s) => s.ui(ui, &mut self.rt),
                        Screen::Backup(s) => s.ui(ui, &mut self.rt),
                        Screen::CreateVault(s) => s.ui(ui, &mut self.rt),
                        Screen::OpenVault(s) => s.ui(ui, &mut self.rt),
                        Screen::Opened(s) => s.ui(ui, &mut self.rt),
                        Screen::Passwd(s) => s.ui(ui, &mut self.rt),
                        Screen::Verify(s) => s.ui(ui, &mut self.rt),
                        Screen::Rekey(s) => s.ui(ui, &mut self.rt),
                    });
            });
        });

        if let Some(next) = self.rt.nav.take() {
            // Leaving an open vault drops it, which wipes its key from memory.
            self.screen = next;
        }
    }
}

// ---------------------------------------------------------------- helpers --

fn has_ext(p: &Path, ext: &str) -> bool {
    p.extension()
        .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case(ext))
}

fn with_ext(mut p: PathBuf, ext: &str) -> PathBuf {
    if !has_ext(&p, ext) {
        let mut s = p.into_os_string();
        s.push(".");
        s.push(ext);
        p = PathBuf::from(s);
    }
    p
}

pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(10.0);
    ui.label(RichText::new(title).strong().size(15.0));
    ui.add_space(2.0);
}

fn warn_text(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(format!("⚠ {text}")).color(ui.visuals().warn_fg_color));
}

fn error_text(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(ui.visuals().error_fg_color));
}

fn primary_button(ui: &mut egui::Ui, enabled: bool, text: &str) -> bool {
    ui.add_space(8.0);
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(text).strong()).min_size(egui::vec2(180.0, 30.0)),
    )
    .clicked()
}

/// A password box. The text lives in a `Zeroizing<String>`; note that egui
/// may keep its own short-lived copies (undo history, layout caches).
fn password_field(ui: &mut egui::Ui, label: &str, value: &mut Zeroizing<String>) {
    ui.horizontal(|ui| {
        let l = ui.add_sized([150.0, 20.0], egui::Label::new(label));
        ui.add(
            egui::TextEdit::singleline(&mut **value)
                .password(true)
                .desired_width(320.0),
        )
        .labelled_by(l.id);
    });
}

/// A new password with confirmation and live policy feedback. Returns the
/// checked password when both boxes agree and the policy accepts it.
fn new_password_fields(
    ui: &mut egui::Ui,
    first: &mut Zeroizing<String>,
    second: &mut Zeroizing<String>,
) -> Option<Password> {
    password_field(ui, "New password", first);
    password_field(ui, "Repeat password", second);
    if first.is_empty() {
        ui.label(RichText::new("At least 15 characters. A few random words work well.").weak());
        return None;
    }
    match Password::new_checked(first) {
        Err(e) => {
            error_text(ui, &e.to_string());
            None
        }
        Ok(p) if **first == **second => Some(p),
        Ok(_) => {
            if !second.is_empty() {
                error_text(ui, "The passwords do not match.");
            }
            None
        }
    }
}

#[derive(Clone, Copy)]
enum Pick {
    OpenKey,
    SaveKey,
    OpenVault,
    SaveVault,
}

fn pick(kind: Pick, default_name: &str) -> Option<PathBuf> {
    let d = rfd::FileDialog::new();
    match kind {
        Pick::OpenKey => d
            .add_filter("Securidge key file", &[keyfile::EXTENSION])
            .pick_file(),
        Pick::SaveKey => d
            .add_filter("Securidge key file", &[keyfile::EXTENSION])
            .set_file_name(default_name)
            .save_file()
            .map(|p| with_ext(p, keyfile::EXTENSION)),
        Pick::OpenVault => d
            .add_filter("Securidge vault", &[vault::EXTENSION])
            .pick_file(),
        Pick::SaveVault => d
            .add_filter("Securidge vault", &[vault::EXTENSION])
            .set_file_name(default_name)
            .save_file()
            .map(|p| with_ext(p, vault::EXTENSION)),
    }
}

/// A path chosen with a Browse button.
fn path_row(
    ui: &mut egui::Ui,
    label: &str,
    path: &Option<PathBuf>,
    kind: Pick,
    default_name: &str,
) -> Option<PathBuf> {
    let mut chosen = None;
    ui.horizontal(|ui| {
        ui.add_sized([150.0, 20.0], egui::Label::new(label));
        if ui.button("Browse…").clicked() {
            chosen = pick(kind, default_name);
        }
        match path {
            Some(p) => ui.label(RichText::new(p.display().to_string()).monospace()),
            None => ui.label(RichText::new("not chosen").weak()),
        };
    });
    chosen
}

/// A chosen key file and what its header says.
#[derive(Default)]
pub struct KeyPick {
    pub path: Option<PathBuf>,
    id: Option<Result<KeyId, String>>,
}

impl KeyPick {
    pub fn set(&mut self, p: PathBuf) {
        self.id = Some(std::fs::read(&p).map_err(|e| e.to_string()).and_then(|b| {
            keyfile::inspect(&b)
                .map(|(id, _)| id)
                .map_err(|e| e.to_string())
        }));
        self.path = Some(p);
    }

    fn id(&self) -> Option<KeyId> {
        self.id.as_ref().and_then(|r| r.as_ref().ok().copied())
    }

    fn ui(&mut self, ui: &mut egui::Ui, label: &str, vault: Option<&Path>) {
        if let Some(p) = path_row(ui, label, &self.path, Pick::OpenKey, "") {
            self.set(p);
        }
        match &self.id {
            Some(Ok(id)) => {
                ui.label(RichText::new(format!("Key id {id}")).weak());
                if let Some(p) = &self.path {
                    for w in advice::key_location(p, vault) {
                        warn_text(ui, w.message());
                    }
                }
            }
            Some(Err(e)) => error_text(ui, e),
            None => {}
        }
    }
}

/// A chosen vault file and which key it needs.
#[derive(Default)]
pub struct VaultPick {
    pub path: Option<PathBuf>,
    needs: Option<Result<KeyId, String>>,
}

impl VaultPick {
    pub fn set(&mut self, p: PathBuf) {
        self.needs = Some(Vault::peek_key_id(&p).map_err(|e| e.to_string()));
        self.path = Some(p);
    }

    fn needs(&self) -> Option<KeyId> {
        self.needs.as_ref().and_then(|r| r.as_ref().ok().copied())
    }

    fn ui(&mut self, ui: &mut egui::Ui) {
        if let Some(p) = path_row(ui, "Vault", &self.path, Pick::OpenVault, "") {
            self.set(p);
        }
        match &self.needs {
            Some(Ok(id)) => {
                ui.label(RichText::new(format!("Needs the key file with key id {id}")).weak());
            }
            Some(Err(e)) => error_text(ui, e),
            None => {}
        }
    }
}

// ------------------------------------------------------------------- home --

fn home_ui(ui: &mut egui::Ui, rt: &mut Runtime) {
    ui.add_space(12.0);
    ui.label(
        "Encrypted archives that open only with both your key file and your password. \
         There is no recovery: lose either one and the data is gone.",
    );
    ui.add_space(12.0);

    let big = |ui: &mut egui::Ui, title: &str, sub: &str| -> bool {
        let clicked = ui
            .add(
                egui::Button::new(RichText::new(title).strong().size(16.0))
                    .min_size(egui::vec2(260.0, 40.0)),
            )
            .clicked();
        ui.label(RichText::new(sub).weak());
        ui.add_space(8.0);
        clicked
    };

    ui.columns(2, |cols| {
        let ui = &mut cols[0];
        section(ui, "Vaults");
        if big(ui, "Open a vault", "List, extract, add or remove files.") {
            rt.go(Screen::OpenVault(OpenVault::default()));
        }
        if big(
            ui,
            "Create a vault",
            "Pack files and folders into a new .svault.",
        ) {
            rt.go(Screen::CreateVault(CreateVault::default()));
        }
        ui.label(RichText::new("Tip: drop files or a .svault here.").weak());

        let ui = &mut cols[1];
        section(ui, "Key files");
        if big(
            ui,
            "Create a key file",
            "Start here. Includes making two backups.",
        ) {
            rt.go(Screen::NewKey(NewKey::default()));
        }
        if big(
            ui,
            "Verify a backup",
            "Check that a key file copy still opens.",
        ) {
            rt.go(Screen::Verify(Verify::default()));
        }
        if big(ui, "Change password", "Same key, new password.") {
            rt.go(Screen::Passwd(Passwd::default()));
        }
        if big(ui, "Rekey vaults", "Move vaults to a brand-new key file.") {
            rt.go(Screen::Rekey(Rekey::default()));
        }
    });

    ui.add_space(16.0);
    warn_text(
        ui,
        "Pre-alpha software, not independently audited. Keep other copies of anything you cannot afford to lose.",
    );
}

// ---------------------------------------------------------------- new key --

#[derive(Default)]
pub struct NewKey {
    pub out: Option<PathBuf>,
    pub pw1: Zeroizing<String>,
    pub pw2: Zeroizing<String>,
}

impl NewKey {
    fn ui(&mut self, ui: &mut egui::Ui, rt: &mut Runtime) {
        ui.heading("Create a key file");
        ui.label("Step 1 of 3: choose a password and where to save the key file. Steps 2 and 3 make and check two backups.");
        section(ui, "Password");
        let pw = new_password_fields(ui, &mut self.pw1, &mut self.pw2);
        section(ui, "Location");
        if let Some(p) = path_row(
            ui,
            "Save key file to",
            &self.out,
            Pick::SaveKey,
            "my-key.svkey",
        ) {
            self.out = Some(p);
        }
        let mut exists = false;
        if let Some(p) = &self.out {
            exists = p.exists();
            if exists {
                error_text(ui, "That file already exists. Choose a new name.");
            }
            for w in advice::key_location(p, None) {
                warn_text(ui, w.message());
            }
        }
        let ready = pw.is_some() && self.out.is_some() && !exists;
        if primary_button(ui, ready, "Create key file") {
            let (Some(pw), Some(out)) = (pw, self.out.clone()) else {
                return;
            };
            self.pw1 = Zeroizing::default();
            self.pw2 = Zeroizing::default();
            let cfg = rt.cfg;
            rt.spawn("Creating key file", move || {
                let r = keyfile::create_file(&out, &pw, cfg.params, &cfg.limits)
                    .and_then(|k| Ok((k.key_id(), std::fs::read(&out)?)));
                Box::new(move |app: &mut App| match r {
                    Ok((id, bytes)) => {
                        ok(
                            app,
                            format!(
                                "Created {} (key id {id}). Now make two backups.",
                                out.display()
                            ),
                        );
                        app.rt.go(Screen::Backup(Backup::new(out, bytes)));
                    }
                    Err(e) => fail(app, format!("Could not create the key file: {e}")),
                })
            });
        }
    }
}

// ----------------------------------------------------------------- backup --

pub struct Backup {
    pub primary: PathBuf,
    bytes: Zeroizing<Vec<u8>>,
    pub copies: [Option<PathBuf>; 2],
    copy_errors: [Option<String>; 2],
    pub pw: Zeroizing<String>,
    pub accept_risk: bool,
    pub verified: bool,
}

impl Backup {
    pub fn new(primary: PathBuf, bytes: Vec<u8>) -> Self {
        Backup {
            primary,
            bytes: Zeroizing::new(bytes),
            copies: [None, None],
            copy_errors: [None, None],
            pw: Zeroizing::default(),
            accept_risk: false,
            verified: false,
        }
    }

    /// Checks a proposed backup location against the others.
    pub fn check_location(&self, slot: usize, p: &Path) -> Result<(), String> {
        let folder = |x: &Path| advice::absolute(x).parent().map(Path::to_path_buf);
        let mut others = vec![self.primary.clone()];
        others.extend(
            self.copies
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != slot)
                .filter_map(|(_, c)| c.clone()),
        );
        for o in &others {
            if folder(o) == folder(p) {
                return Err(format!(
                    "{} is in the same folder as another copy. Use a different drive or folder.",
                    p.display()
                ));
            }
        }
        if p.exists() {
            return Err(format!("{} already exists.", p.display()));
        }
        Ok(())
    }

    /// Writes backup copy `slot` to `p` (exact bytes, read back to confirm).
    pub fn write_copy(&mut self, slot: usize, p: PathBuf) {
        self.copy_errors[slot] = None;
        let r = self
            .check_location(slot, &p)
            .and_then(|()| keyfile::write_copy(&p, &self.bytes).map_err(|e| e.to_string()));
        match r {
            Ok(()) => self.copies[slot] = Some(p),
            Err(e) => self.copy_errors[slot] = Some(e),
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, rt: &mut Runtime) {
        ui.heading("Back up your key file");
        if self.verified {
            ui.label(RichText::new("✔ All copies verified.").strong());
            ui.label(format!("Original: {}", self.primary.display()));
            for c in self.copies.iter().flatten() {
                ui.label(format!("Backup: {}", c.display()));
            }
            ui.add_space(6.0);
            ui.label("Keep the copies in separate places. Verify a backup now and then (Home > Verify a backup).");
            if primary_button(ui, true, "Done") {
                rt.go(Screen::Home);
            }
            return;
        }

        ui.label(
            "There is no recovery. If you lose every copy of this key file, or forget the password, \
             every vault made with it is lost for good. Save two backups now, ideally on two \
             different USB drives.",
        );
        ui.label(format!("Original: {}", self.primary.display()));

        section(ui, "Step 2 of 3: two backup copies");
        let primary_vol = advice::volume(&self.primary);
        for slot in 0..2 {
            let label = format!("Backup {}", slot + 1);
            match self.copies[slot].clone() {
                Some(p) => {
                    ui.horizontal(|ui| {
                        ui.add_sized([150.0, 20.0], egui::Label::new(&label));
                        ui.label(format!("✔ {}", p.display()));
                    });
                    if primary_vol.is_some() && advice::volume(&p) == primary_vol {
                        warn_text(ui, "Same drive as the original: if that drive fails, both copies are lost.");
                    }
                }
                None => {
                    let name = self
                        .primary
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "my-key.svkey".into());
                    if let Some(p) = path_row(ui, &label, &None, Pick::SaveKey, &name) {
                        self.write_copy(slot, p);
                    }
                    if let Some(e) = &self.copy_errors[slot] {
                        error_text(ui, e);
                    }
                }
            }
        }

        let both = self.copies.iter().all(Option::is_some);
        section(ui, "Step 3 of 3: check the copies");
        ui.label("Type the password once more. This reads every copy back and confirms the password opens it.");
        password_field(ui, "Password", &mut self.pw);
        if primary_button(ui, both && !self.pw.is_empty(), "Verify all copies") {
            let pw = Password::new_unchecked(&self.pw);
            self.pw = Zeroizing::default();
            let mut files = vec![self.primary.clone()];
            files.extend(self.copies.iter().flatten().cloned());
            let expected = self.bytes.clone();
            let limits = rt.cfg.limits;
            rt.spawn("Verifying copies", move || {
                let r = verify_copies(&files, &expected, &pw, &limits);
                Box::new(move |app: &mut App| match r {
                    Ok(id) => {
                        if let Screen::Backup(b) = &mut app.screen {
                            b.verified = true;
                        }
                        ok(
                            app,
                            format!("All {} copies match and open (key id {id}).", files.len()),
                        );
                    }
                    Err(e) => fail(app, e),
                })
            });
        }

        ui.add_space(16.0);
        ui.separator();
        ui.checkbox(
            &mut self.accept_risk,
            "I accept that if I lose this key file or forget the password, my data is gone.",
        );
        if ui
            .add_enabled(self.accept_risk, egui::Button::new("Skip backups"))
            .clicked()
        {
            info_nav(
                rt,
                format!(
                    "Backups skipped. Only one copy exists: {}",
                    self.primary.display()
                ),
            );
        }
    }
}

fn info_nav(rt: &mut Runtime, text: String) {
    rt.notice = Some(Notice {
        kind: NoticeKind::Info,
        text,
    });
    rt.go(Screen::Home);
}

/// Every copy must hold exactly the original bytes, and the password must
/// open them. Identical bytes means one unlock proves all copies.
pub fn verify_copies(
    files: &[PathBuf],
    expected: &[u8],
    pw: &Password,
    limits: &KdfLimits,
) -> Result<KeyId, String> {
    for f in files {
        let b = std::fs::read(f).map_err(|e| format!("Cannot read {}: {e}", f.display()))?;
        if b != expected {
            return Err(format!(
                "{} differs from the original key file.",
                f.display()
            ));
        }
    }
    keyfile::open(expected, pw, limits)
        .map(|k| k.key_id())
        .map_err(|e| e.to_string())
}

// ----------------------------------------------------------- create vault --

#[derive(Default)]
pub struct CreateVault {
    pub key: KeyPick,
    pub inputs: Vec<PathBuf>,
    pub out: Option<PathBuf>,
    pub pw: Zeroizing<String>,
}

impl CreateVault {
    fn ui(&mut self, ui: &mut egui::Ui, rt: &mut Runtime) {
        ui.heading("Create a vault");
        section(ui, "Files and folders");
        ui.horizontal(|ui| {
            if ui.button("Add files…").clicked() {
                if let Some(ps) = rfd::FileDialog::new().pick_files() {
                    self.inputs.extend(ps);
                }
            }
            if ui.button("Add folder…").clicked() {
                if let Some(ps) = rfd::FileDialog::new().pick_folders() {
                    self.inputs.extend(ps);
                }
            }
            ui.label(RichText::new("or drop them on this window").weak());
        });
        self.inputs.sort();
        self.inputs.dedup();
        let mut remove = None;
        for (i, p) in self.inputs.iter().enumerate() {
            ui.horizontal(|ui| {
                if ui
                    .small_button("×")
                    .on_hover_text("Remove from list")
                    .clicked()
                {
                    remove = Some(i);
                }
                let tag = if p.is_dir() { "📁" } else { "📄" };
                ui.label(format!("{tag} {}", p.display()));
            });
        }
        if let Some(i) = remove {
            self.inputs.remove(i);
        }

        section(ui, "Save as");
        if let Some(p) = path_row(
            ui,
            "Vault file",
            &self.out,
            Pick::SaveVault,
            "my-files.svault",
        ) {
            self.out = Some(p);
        }
        let exists = self.out.as_ref().is_some_and(|p| p.exists());
        if exists {
            error_text(ui, "That file already exists. Choose a new name.");
        }

        section(ui, "Key");
        self.key.ui(ui, "Key file", self.out.as_deref());
        password_field(ui, "Password", &mut self.pw);

        let ready = !self.inputs.is_empty()
            && self.out.is_some()
            && !exists
            && self.key.id().is_some()
            && !self.pw.is_empty();
        if primary_button(ui, ready, "Create vault") {
            let pw = Password::new_unchecked(&self.pw);
            self.pw = Zeroizing::default();
            let key = self.key.path.clone().expect("checked");
            let out = self.out.clone().expect("checked");
            let inputs = self.inputs.clone();
            let limits = rt.cfg.limits;
            rt.spawn("Unlocking key and encrypting", move || {
                let r = keyfile::open_file(&key, &pw, &limits)
                    .and_then(|k| Vault::create(&out, &k, &inputs));
                Box::new(move |app: &mut App| match r {
                    Ok((v, skipped)) => {
                        let mut msg = format!(
                            "Created {} with {} file(s).",
                            out.display(),
                            v.entries().len()
                        );
                        if !skipped.is_empty() {
                            msg.push_str(&format!(
                                " Skipped {} link(s) or special file(s).",
                                skipped.len()
                            ));
                        }
                        ok(app, msg);
                        app.rt.go(Screen::Opened(Opened::new(v)));
                    }
                    Err(e) => fail(app, e.to_string()),
                })
            });
        }
    }
}

// ------------------------------------------------------------- open vault --

#[derive(Default)]
pub struct OpenVault {
    pub vault: VaultPick,
    pub key: KeyPick,
    pub pw: Zeroizing<String>,
}

impl OpenVault {
    fn ui(&mut self, ui: &mut egui::Ui, rt: &mut Runtime) {
        ui.heading("Open a vault");
        section(ui, "Vault");
        self.vault.ui(ui);
        section(ui, "Key");
        self.key.ui(ui, "Key file", self.vault.path.as_deref());
        let mismatch = matches!((self.vault.needs(), self.key.id()), (Some(a), Some(b)) if a != b);
        if mismatch {
            error_text(ui, "This key file does not belong to this vault.");
        }
        password_field(ui, "Password", &mut self.pw);
        let ready = self.vault.needs().is_some()
            && self.key.id().is_some()
            && !mismatch
            && !self.pw.is_empty();
        if primary_button(ui, ready, "Open") {
            let pw = Password::new_unchecked(&self.pw);
            self.pw = Zeroizing::default();
            let key = self.key.path.clone().expect("checked");
            let path = self.vault.path.clone().expect("checked");
            let limits = rt.cfg.limits;
            rt.spawn("Unlocking key file", move || {
                let r = keyfile::open_file(&key, &pw, &limits).and_then(|k| Vault::open(&path, &k));
                Box::new(move |app: &mut App| match r {
                    Ok(v) => app.rt.go(Screen::Opened(Opened::new(v))),
                    Err(e) => fail(app, e.to_string()),
                })
            });
        }
    }
}

// ---------------------------------------------------------- opened vault --

pub struct Opened {
    /// `None` while a worker is using it.
    vault: Option<Vault>,
    path: PathBuf,
    pub selected: HashSet<String>,
    pub filter: String,
    pub overwrite: bool,
    pub replace: bool,
    confirm_remove: bool,
}

impl Opened {
    pub fn new(v: Vault) -> Self {
        Opened {
            path: v.path().to_path_buf(),
            vault: Some(v),
            selected: HashSet::new(),
            filter: String::new(),
            overwrite: false,
            replace: false,
            confirm_remove: false,
        }
    }

    pub fn vault(&self) -> Option<&Vault> {
        self.vault.as_ref()
    }

    /// Runs `op` on the vault in a worker, then puts the vault back.
    fn run(
        &mut self,
        rt: &mut Runtime,
        label: &str,
        op: impl FnOnce(&mut Vault) -> Result<String, String> + Send + 'static,
    ) {
        let Some(mut v) = self.vault.take() else {
            return;
        };
        rt.spawn(label, move || {
            let r = op(&mut v);
            Box::new(move |app: &mut App| {
                if let Screen::Opened(s) = &mut app.screen {
                    let names: HashSet<String> =
                        v.entries().iter().map(|e| e.path.clone()).collect();
                    s.selected.retain(|n| names.contains(n));
                    s.vault = Some(v);
                }
                match r {
                    Ok(m) => ok(app, m),
                    Err(e) => fail(app, e),
                }
            })
        });
    }

    fn add(&mut self, rt: &mut Runtime, inputs: Vec<PathBuf>) {
        let replace = self.replace;
        self.run(rt, "Adding", move |v| {
            let before = v.entries().len();
            let skipped = v.add(&inputs, replace).map_err(|e| e.to_string())?;
            let mut m = format!(
                "Vault now holds {} file(s) (was {before}).",
                v.entries().len()
            );
            if !skipped.is_empty() {
                m.push_str(&format!(
                    " Skipped {} link(s) or special file(s).",
                    skipped.len()
                ));
            }
            Ok(m)
        });
    }

    fn extract(&mut self, rt: &mut Runtime, only: Vec<String>) {
        let Some(dest) = rfd::FileDialog::new()
            .set_title("Extract to folder")
            .pick_folder()
        else {
            return;
        };
        let overwrite = self.overwrite;
        self.run(rt, "Extracting", move |v| {
            v.extract(&dest, &only, overwrite)
                .map(|d| format!("Extracted {} file(s) to {}.", d.len(), dest.display()))
                .map_err(|e| e.to_string())
        });
    }

    fn ui(&mut self, ui: &mut egui::Ui, rt: &mut Runtime) {
        ui.heading(
            self.path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        ui.label(RichText::new(self.path.display().to_string()).weak());
        let Some(v) = &self.vault else {
            ui.label("Working…");
            return;
        };
        let total: u64 = v.entries().iter().map(|e| e.size).sum();
        ui.label(format!(
            "{} file(s), {} · key id {}",
            v.entries().len(),
            human_size(total),
            v.key_id()
        ));

        ui.add_space(6.0);
        let n_sel = self.selected.len();
        ui.horizontal_wrapped(|ui| {
            if ui.button("Extract all…").clicked() {
                self.extract(rt, Vec::new());
            }
            if ui
                .add_enabled(
                    n_sel > 0,
                    egui::Button::new(format!("Extract selected ({n_sel})…")),
                )
                .clicked()
            {
                let mut only: Vec<String> = self.selected.iter().cloned().collect();
                only.sort();
                self.extract(rt, only);
            }
            ui.checkbox(&mut self.overwrite, "Overwrite existing files");
        });
        ui.horizontal_wrapped(|ui| {
            if ui.button("Add files…").clicked() {
                if let Some(ps) = rfd::FileDialog::new().pick_files() {
                    self.add(rt, ps);
                }
            }
            if ui.button("Add folder…").clicked() {
                if let Some(ps) = rfd::FileDialog::new().pick_folders() {
                    self.add(rt, ps);
                }
            }
            ui.checkbox(&mut self.replace, "Replace files with the same name");
            if ui
                .add_enabled(
                    n_sel > 0,
                    egui::Button::new(format!("Remove selected ({n_sel})")),
                )
                .clicked()
            {
                self.confirm_remove = true;
            }
            if ui
                .button("🔒 Lock")
                .on_hover_text("Close the vault and wipe its key from memory")
                .clicked()
            {
                rt.go(Screen::Home);
            }
        });

        if self.confirm_remove {
            let n = self.selected.len();
            let mut decision = None;
            let resp = egui::Modal::new(egui::Id::unique("confirm-remove")).show(ui.ctx(), |ui| {
                ui.label(RichText::new(format!("Remove {n} file(s) from the vault?")).strong());
                ui.label("This cannot be undone.");
                ui.horizontal(|ui| {
                    if ui.button("Remove").clicked() {
                        decision = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        decision = Some(false);
                    }
                });
            });
            if resp.should_close() && decision.is_none() {
                decision = Some(false);
            }
            if let Some(d) = decision {
                self.confirm_remove = false;
                if d {
                    let names: Vec<String> = self.selected.iter().cloned().collect();
                    self.run(rt, "Removing", move |v| {
                        v.remove(&names)
                            .map(|r| format!("Removed {} file(s).", r.len()))
                            .map_err(|e| e.to_string())
                    });
                    return;
                }
            }
        }

        let Some(v) = &self.vault else { return };
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let l = ui.label("Filter");
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(240.0))
                .labelled_by(l.id);
            if ui.button("Select shown").clicked() {
                let f = self.filter.to_lowercase();
                for e in v.entries() {
                    if e.path.to_lowercase().contains(&f) {
                        self.selected.insert(e.path.clone());
                    }
                }
            }
            if ui.button("Clear selection").clicked() {
                self.selected.clear();
            }
        });

        let f = self.filter.to_lowercase();
        let rows: Vec<&vault::Entry> = v
            .entries()
            .iter()
            .filter(|e| f.is_empty() || e.path.to_lowercase().contains(&f))
            .collect();
        let selected = &mut self.selected;
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::exact(24.0))
            .column(Column::remainder().clip(true))
            .column(Column::exact(90.0))
            .column(Column::exact(130.0))
            .header(20.0, |mut h| {
                h.col(|_| {});
                h.col(|ui| {
                    ui.strong("Path");
                });
                h.col(|ui| {
                    ui.strong("Size");
                });
                h.col(|ui| {
                    ui.strong("Modified (UTC)");
                });
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let e = rows[row.index()];
                    row.col(|ui| {
                        let mut on = selected.contains(&e.path);
                        if ui.checkbox(&mut on, "").changed() {
                            if on {
                                selected.insert(e.path.clone());
                            } else {
                                selected.remove(&e.path);
                            }
                        }
                    });
                    row.col(|ui| {
                        ui.label(&e.path);
                    });
                    row.col(|ui| {
                        ui.label(human_size(e.size));
                    });
                    row.col(|ui| {
                        ui.label(vault::format_time(e.modified));
                    });
                });
            });
    }
}

// --------------------------------------------------------------- password --

#[derive(Default)]
pub struct Passwd {
    pub key: KeyPick,
    pub old: Zeroizing<String>,
    pub pw1: Zeroizing<String>,
    pub pw2: Zeroizing<String>,
}

impl Passwd {
    fn ui(&mut self, ui: &mut egui::Ui, rt: &mut Runtime) {
        ui.heading("Change password");
        ui.label(
            "The key stays the same, so your vaults keep working. Older copies of this key file \
             (your backups) still open with the OLD password until you replace them. If someone \
             may know the old password, use Rekey instead.",
        );
        section(ui, "Key file");
        self.key.ui(ui, "Key file", None);
        password_field(ui, "Current password", &mut self.old);
        section(ui, "New password");
        let pw = new_password_fields(ui, &mut self.pw1, &mut self.pw2);
        let ready = self.key.id().is_some() && !self.old.is_empty() && pw.is_some();
        if primary_button(ui, ready, "Save new password") {
            let (Some(new), Some(key)) = (pw, self.key.path.clone()) else {
                return;
            };
            let old = Password::new_unchecked(&self.old);
            self.old = Zeroizing::default();
            self.pw1 = Zeroizing::default();
            self.pw2 = Zeroizing::default();
            let cfg = rt.cfg;
            rt.spawn("Re-encrypting key file", move || {
                let r = keyfile::change_password_file(&key, &old, &new, cfg.params, &cfg.limits)
                    .and_then(|()| Ok(std::fs::read(&key)?));
                Box::new(move |app: &mut App| match r {
                    Ok(bytes) => {
                        ok(app, "Password changed. Make fresh backups now; your old backups still use the old password.");
                        app.rt.go(Screen::Backup(Backup::new(key, bytes)));
                    }
                    Err(e) => fail(app, e.to_string()),
                })
            });
        }
    }
}

// ----------------------------------------------------------------- verify --

#[derive(Default)]
pub struct Verify {
    pub key: KeyPick,
    pub pw: Zeroizing<String>,
}

impl Verify {
    fn ui(&mut self, ui: &mut egui::Ui, rt: &mut Runtime) {
        ui.heading("Verify a backup");
        ui.label("Checks that a key file copy is intact and that your password opens it. Nothing is changed.");
        section(ui, "Key file");
        self.key.ui(ui, "Key file", None);
        password_field(ui, "Password", &mut self.pw);
        if primary_button(ui, self.key.id().is_some() && !self.pw.is_empty(), "Verify") {
            let pw = Password::new_unchecked(&self.pw);
            self.pw = Zeroizing::default();
            let key = self.key.path.clone().expect("checked");
            let limits = rt.cfg.limits;
            rt.spawn("Unlocking key file", move || {
                let r = keyfile::open_file(&key, &pw, &limits);
                Box::new(move |app: &mut App| match r {
                    Ok(k) => ok(
                        app,
                        format!(
                            "OK: {} opens correctly (key id {}).",
                            key.display(),
                            k.key_id()
                        ),
                    ),
                    Err(e) => fail(app, e.to_string()),
                })
            });
        }
    }
}

// ------------------------------------------------------------------ rekey --

#[derive(Default)]
pub struct Rekey {
    pub key: KeyPick,
    pub pw: Zeroizing<String>,
    pub vaults: Vec<VaultPick>,
    pub new_key: Option<PathBuf>,
    pub pw1: Zeroizing<String>,
    pub pw2: Zeroizing<String>,
}

impl Rekey {
    pub fn add_vault(&mut self, p: PathBuf) {
        if self.vaults.iter().any(|v| v.path.as_ref() == Some(&p)) {
            return;
        }
        let mut v = VaultPick::default();
        v.set(p);
        self.vaults.push(v);
    }

    fn ui(&mut self, ui: &mut egui::Ui, rt: &mut Runtime) {
        ui.heading("Rekey vaults");
        ui.label(
            "Creates a brand-new key file and re-encrypts the listed vaults for it. Afterwards the old \
             key file (and every copy of it) can no longer open them. Use this if a key file copy or \
             the password may have leaked.",
        );
        section(ui, "Current key");
        self.key.ui(ui, "Current key file", None);
        password_field(ui, "Current password", &mut self.pw);

        section(ui, "Vaults to move");
        if ui.button("Add vaults…").clicked() {
            if let Some(ps) = rfd::FileDialog::new()
                .add_filter("Securidge vault", &[vault::EXTENSION])
                .pick_files()
            {
                for p in ps {
                    self.add_vault(p);
                }
            }
        }
        let cur = self.key.id();
        let mut remove = None;
        let mut all_match = !self.vaults.is_empty();
        for (i, v) in self.vaults.iter().enumerate() {
            ui.horizontal(|ui| {
                if ui.small_button("×").clicked() {
                    remove = Some(i);
                }
                let p = v
                    .path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                match (v.needs(), cur) {
                    (Some(n), Some(c)) if n == c => {
                        ui.label(format!("✔ {p}"));
                    }
                    (Some(_), Some(_)) => {
                        all_match = false;
                        error_text(ui, &format!("{p}: belongs to a different key file"));
                    }
                    (None, _) => {
                        all_match = false;
                        error_text(ui, &format!("{p}: not a readable vault"));
                    }
                    (Some(_), None) => {
                        all_match = false;
                        ui.label(&p);
                    }
                }
            });
        }
        if let Some(i) = remove {
            self.vaults.remove(i);
        }
        ui.label(RichText::new("Vaults you do not list keep needing the OLD key file.").weak());

        section(ui, "New key file");
        if let Some(p) = path_row(
            ui,
            "Save new key file to",
            &self.new_key,
            Pick::SaveKey,
            "new-key.svkey",
        ) {
            self.new_key = Some(p);
        }
        let exists = self.new_key.as_ref().is_some_and(|p| p.exists());
        if exists {
            error_text(ui, "That file already exists. Choose a new name.");
        }
        let pw = new_password_fields(ui, &mut self.pw1, &mut self.pw2);

        let ready = cur.is_some()
            && !self.pw.is_empty()
            && all_match
            && !exists
            && self.new_key.is_some()
            && pw.is_some();
        if primary_button(ui, ready, "Rekey") {
            let (Some(new_pw), Some(new_path), Some(old_path)) =
                (pw, self.new_key.clone(), self.key.path.clone())
            else {
                return;
            };
            let old_pw = Password::new_unchecked(&self.pw);
            self.pw = Zeroizing::default();
            self.pw1 = Zeroizing::default();
            self.pw2 = Zeroizing::default();
            let vaults: Vec<PathBuf> = self.vaults.iter().filter_map(|v| v.path.clone()).collect();
            let cfg = rt.cfg;
            rt.spawn("Rekeying", move || {
                let r = rekey_all(&old_path, &old_pw, &vaults, &new_path, &new_pw, cfg);
                Box::new(move |app: &mut App| match r {
                    Err(e) => fail(app, e),
                    Ok((bytes, done, err)) => {
                        let mut msg = format!(
                            "Rekeyed {} vault(s). Back up the new key file now, then destroy every copy of the old one.",
                            done.len()
                        );
                        if let Some(e) = err {
                            msg = format!(
                                "Rekeyed {} vault(s), then stopped: {e}. Vaults not yet rekeyed still need the OLD key file. Back up the new key file now.",
                                done.len()
                            );
                            fail(app, msg);
                        } else {
                            ok(app, msg);
                        }
                        app.rt.go(Screen::Backup(Backup::new(new_path, bytes)));
                    }
                })
            });
        }
    }
}

/// Returns the new key file's bytes, the vaults rekeyed, and the first
/// error if one stopped the run part-way. `Err` means no vault was changed
/// (a new key file may exist if only its read-back failed).
type RekeyResult = (Vec<u8>, Vec<PathBuf>, Option<String>);

pub fn rekey_all(
    old_path: &Path,
    old_pw: &Password,
    vaults: &[PathBuf],
    new_path: &Path,
    new_pw: &Password,
    cfg: Config,
) -> Result<RekeyResult, String> {
    let old = keyfile::open_file(old_path, old_pw, &cfg.limits).map_err(|e| e.to_string())?;
    // The same vault under two spellings (case, links) must be rekeyed once.
    let mut unique: Vec<PathBuf> = Vec::new();
    for v in vaults {
        let c = v
            .canonicalize()
            .map_err(|e| format!("{}: {e}", v.display()))?;
        if !unique.contains(&c) {
            unique.push(c);
        }
    }
    let vaults = &unique;
    for v in vaults {
        let id = Vault::peek_key_id(v).map_err(|e| format!("{}: {e}", v.display()))?;
        if id != old.key_id() {
            return Err(format!(
                "{} does not belong to this key file; nothing was changed",
                v.display()
            ));
        }
    }
    let new = UnlockedKey::generate();
    // Write the new key first: if a vault fails below, the user still holds
    // a key for every vault (old or new).
    let bytes = keyfile::seal(&new, new_pw, cfg.params, &cfg.limits)
        .map_err(|e| format!("Could not create the new key: {e}"))?
        .to_vec();
    keyfile::write_copy(new_path, &bytes)
        .map_err(|e| format!("Could not write the new key file: {e}"))?;
    let mut done = Vec::new();
    for v in vaults {
        if let Err(e) = vault::rekey(v, &old, &new) {
            return Ok((bytes, done, Some(format!("{}: {e}", v.display()))));
        }
        done.push(v.clone());
    }
    Ok((bytes, done, None))
}
