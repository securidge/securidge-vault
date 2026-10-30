//! `securidge-vault` command-line interface.
//!
//! Every command that opens a vault needs both `--key <file.svkey>` and the
//! key file's password. Passwords are read from the terminal without echo,
//! or one per line from stdin with `--password-stdin` (for automation).

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use vault_core::keyfile;
use vault_core::{vault, KdfLimits, KdfParams, Password, UnlockedKey, Vault};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "securidge-vault",
    version,
    about = "Encrypted archives that need both a key file and a password."
)]
struct Cli {
    /// Read passwords from stdin, one per line, instead of prompting.
    #[arg(long, global = true)]
    password_stdin: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new key file.
    Keygen {
        /// Where to save the key file (.svkey).
        #[arg(long)]
        out: PathBuf,
    },
    /// Change the password of a key file (does not invalidate old copies; see `rekey`).
    Passwd {
        #[arg(long)]
        key: PathBuf,
    },
    /// Check that a key file opens with its password (use on every backup).
    VerifyKey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Create a vault from files and folders.
    Create {
        /// Vault to create (.svault).
        vault: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Files and folders to add.
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },
    /// List the contents of a vault.
    List {
        vault: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Extract all entries, or only the given paths/folders.
    Extract {
        vault: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Destination folder.
        #[arg(long)]
        dest: PathBuf,
        /// Overwrite existing files in the destination.
        #[arg(long)]
        overwrite: bool,
        /// Paths or folders inside the vault (default: everything).
        entries: Vec<String>,
    },
    /// Add files and folders to an existing vault.
    Add {
        vault: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Replace entries that already exist.
        #[arg(long)]
        replace: bool,
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },
    /// Remove entries (paths or folders) from a vault.
    Remove {
        vault: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(required = true)]
        entries: Vec<String>,
    },
    /// Move vaults to a brand-new key. Old key file copies stop working for them.
    Rekey {
        /// Current key file.
        #[arg(long)]
        key: PathBuf,
        /// Where to save the new key file.
        #[arg(long)]
        new_key: PathBuf,
        #[arg(required = true)]
        vaults: Vec<PathBuf>,
    },
    /// Show which key file a vault needs (no password required).
    Info { vault: PathBuf },
}

struct Prompter {
    stdin: bool,
}

impl Prompter {
    fn read(&self, prompt: &str) -> Result<Zeroizing<String>> {
        if self.stdin {
            let mut line = Zeroizing::new(String::new());
            io::stdin().lock().read_line(&mut line)?;
            let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
            if trimmed.is_empty() {
                bail!("expected a password on stdin");
            }
            Ok(Zeroizing::new(trimmed))
        } else {
            Ok(Zeroizing::new(
                rpassword::prompt_password(prompt).context("could not read password")?,
            ))
        }
    }

    /// Existing password: no policy check.
    fn existing(&self, prompt: &str) -> Result<Password> {
        Ok(Password::new_unchecked(&self.read(prompt)?))
    }

    /// New password: policy check, and confirmation when interactive.
    fn new_password(&self, prompt: &str) -> Result<Password> {
        loop {
            let first = self.read(prompt)?;
            match Password::new_checked(&first) {
                Err(e) if !self.stdin => {
                    eprintln!("{e}");
                    continue;
                }
                Err(e) => return Err(e.into()),
                Ok(p) => {
                    if !self.stdin {
                        let second = self.read("Repeat password: ")?;
                        if *second != *first {
                            eprintln!("Passwords do not match. Try again.");
                            continue;
                        }
                    }
                    return Ok(p);
                }
            }
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let p = Prompter {
        stdin: cli.password_stdin,
    };
    let limits = KdfLimits::PRODUCTION;
    let params = KdfParams::DEFAULT;

    match cli.cmd {
        Cmd::Keygen { out } => {
            refuse_existing(&out)?;
            warn_key_location(&out, None);
            eprintln!("Choose a password of at least 15 characters. A few random words work well.");
            let pw = p.new_password("New password: ")?;
            let k = timed("Creating key file", || {
                keyfile::create_file(&out, &pw, params, &limits)
            })?;
            println!("Created key file {} (key id {})", out.display(), k.key_id());
            eprintln!();
            eprintln!("IMPORTANT: there is no recovery. If you lose this file or forget the");
            eprintln!("password, every vault made with it is gone for good.");
            eprintln!("Copy it to at least two separate places now (e.g. two USB drives),");
            eprintln!("then run `securidge-vault verify-key --key <copy>` on each copy.");
        }
        Cmd::Passwd { key } => {
            let old = p.existing("Current password: ")?;
            let new = p.new_password("New password: ")?;
            timed("Re-encrypting key file", || {
                keyfile::change_password_file(&key, &old, &new, params, &limits)
            })?;
            println!("Password changed for {}.", key.display());
            eprintln!("Note: older copies of this key file still open with the old password.");
            eprintln!(
                "Update your backups. If the old password may be known to someone, use `rekey`."
            );
        }
        Cmd::VerifyKey { key } => {
            let k = unlock(&p, &key, &limits)?;
            println!(
                "OK: {} opens correctly (key id {}).",
                key.display(),
                k.key_id()
            );
        }
        Cmd::Info { vault } => {
            let id = Vault::peek_key_id(&vault)?;
            println!("{} needs the key file with key id {id}.", vault.display());
        }
        Cmd::Create { vault, key, inputs } => {
            refuse_existing(&vault)?;
            warn_key_location(&key, Some(&vault));
            let k = unlock(&p, &key, &limits)?;
            let (v, skipped) = timed("Encrypting", || Vault::create(&vault, &k, &inputs))?;
            report_skipped(&skipped);
            println!(
                "Created {} with {} file(s).",
                vault.display(),
                v.entries().len()
            );
        }
        Cmd::List { vault, key } => {
            let k = unlock_for(&p, &key, &vault, &limits)?;
            let v = Vault::open(&vault, &k)?;
            let mut total = 0u64;
            println!("{:>14}  {:<16}  path", "size", "modified (UTC)");
            for e in v.entries() {
                total += e.size;
                println!(
                    "{:>14}  {:<16}  {}",
                    e.size,
                    vault::format_time(e.modified),
                    e.path
                );
            }
            println!("{} file(s), {} bytes", v.entries().len(), total);
        }
        Cmd::Extract {
            vault,
            key,
            dest,
            overwrite,
            entries,
        } => {
            let k = unlock_for(&p, &key, &vault, &limits)?;
            let v = Vault::open(&vault, &k)?;
            let done = timed("Extracting", || v.extract(&dest, &entries, overwrite))?;
            println!("Extracted {} file(s) to {}.", done.len(), dest.display());
        }
        Cmd::Add {
            vault,
            key,
            replace,
            inputs,
        } => {
            let k = unlock_for(&p, &key, &vault, &limits)?;
            let mut v = Vault::open(&vault, &k)?;
            let before = v.entries().len();
            let skipped = timed("Adding", || v.add(&inputs, replace))?;
            report_skipped(&skipped);
            println!(
                "{} now holds {} file(s) (was {before}).",
                vault.display(),
                v.entries().len()
            );
        }
        Cmd::Remove {
            vault,
            key,
            entries,
        } => {
            let k = unlock_for(&p, &key, &vault, &limits)?;
            let mut v = Vault::open(&vault, &k)?;
            let removed = v.remove(&entries)?;
            for r in &removed {
                println!("removed {r}");
            }
            println!(
                "{} now holds {} file(s).",
                vault.display(),
                v.entries().len()
            );
        }
        Cmd::Rekey {
            key,
            new_key,
            vaults,
        } => {
            refuse_existing(&new_key)?;
            let old = unlock(&p, &key, &limits)?;
            for v in &vaults {
                let id = Vault::peek_key_id(v)?;
                if id != old.key_id() {
                    bail!(
                        "{} does not belong to {}; nothing was changed",
                        v.display(),
                        key.display()
                    );
                }
            }
            eprintln!("Choose the password for the NEW key file.");
            let pw = p.new_password("New password: ")?;
            let new = UnlockedKey::generate();
            // Write the new key file first: if anything below fails, the user
            // still holds a key for every vault (old or new).
            timed("Creating new key file", || {
                keyfile::write_file(&new_key, &new, &pw, params, &limits)
            })?;
            for v in &vaults {
                vault::rekey(v, &old, &new)
                    .with_context(|| format!("rekey failed for {}", v.display()))?;
                println!("rekeyed {}", v.display());
            }
            println!(
                "New key file: {} (key id {})",
                new_key.display(),
                new.key_id()
            );
            eprintln!("Back up the new key file now, then destroy every copy of the old one.");
            eprintln!("Vaults you did not list here still need the OLD key file.");
        }
    }
    Ok(())
}

fn unlock(p: &Prompter, key: &Path, limits: &KdfLimits) -> Result<UnlockedKey> {
    let bytes =
        std::fs::read(key).with_context(|| format!("cannot read key file {}", key.display()))?;
    keyfile::inspect(&bytes)?;
    let pw = p.existing("Password: ")?;
    Ok(timed("Unlocking key file", || {
        keyfile::open(&bytes, &pw, limits)
    })?)
}

/// Unlocks `key` after checking it is the key `vault` needs, so the user is
/// not asked for a password that cannot work.
fn unlock_for(p: &Prompter, key: &Path, vault: &Path, limits: &KdfLimits) -> Result<UnlockedKey> {
    let needed = Vault::peek_key_id(vault)?;
    let bytes =
        std::fs::read(key).with_context(|| format!("cannot read key file {}", key.display()))?;
    let (have, _) = keyfile::inspect(&bytes)?;
    if have != needed {
        bail!(
            "{} needs key id {needed}, but {} is key id {have}",
            vault.display(),
            key.display()
        );
    }
    warn_key_location(key, Some(vault));
    unlock(p, key, limits)
}

fn timed<T, E>(
    label: &str,
    f: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    eprint!("{label}... ");
    let _ = io::stderr().flush();
    let start = Instant::now();
    let r = f();
    eprintln!(
        "{} ({:.1}s)",
        if r.is_ok() { "done" } else { "failed" },
        start.elapsed().as_secs_f64()
    );
    r
}

fn refuse_existing(path: &Path) -> Result<()> {
    if path.exists() {
        bail!(
            "{} already exists; refusing to overwrite it",
            path.display()
        );
    }
    Ok(())
}

fn report_skipped(skipped: &[PathBuf]) {
    for s in skipped {
        eprintln!("skipped (link or special file): {}", s.display());
    }
}

/// DESIGN.md §5.2: warn about risky key file locations. Never blocks.
fn warn_key_location(key: &Path, vault: Option<&Path>) {
    let abs = |p: &Path| -> PathBuf {
        let parent = p
            .parent()
            .filter(|x| !x.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        parent
            .canonicalize()
            .map(|d| d.join(p.file_name().unwrap_or_default()))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    let key_abs = abs(key);
    let lower = key_abs.to_string_lossy().to_lowercase();

    if let Some(v) = vault {
        if abs(v).parent() == key_abs.parent() {
            eprintln!("warning: the key file is in the same folder as the vault. Anyone who copies the folder gets both.");
        }
    }
    if [
        "onedrive",
        "dropbox",
        "google drive",
        "googledrive",
        "icloud",
    ]
    .iter()
    .any(|s| lower.contains(s))
    {
        eprintln!(
            "warning: the key file is in a cloud-synced folder. A copy may be stored online."
        );
    }
    #[cfg(windows)]
    {
        let sys = std::env::var("SystemDrive")
            .unwrap_or_else(|_| "C:".into())
            .to_lowercase();
        let path = lower.trim_start_matches(r"\\?\");
        if path.starts_with(&sys) {
            eprintln!("warning: the key file is on the system drive. Malware that steals files can find it; prefer a USB drive.");
        }
    }
}
