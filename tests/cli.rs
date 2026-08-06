//! End-to-end CLI tests driven through a real pseudo-terminal.
//!
//! sk2 reads every password with `rpassword`, which talks to the terminal device
//! directly, so piped stdin cannot drive it — which is why `main.rs` and every
//! interactive path went untested for so long. These tests allocate a real PTY,
//! spawn the built binary on it, and answer each prompt as it appears. This is the
//! layer `testing.md` calls Layer 3.
//!
//! Unix only. Windows has no equivalent, and CI still runs the unit suite there.
//!
//! Two things deliberately avoided:
//!
//! * **`get` is not asserted on.** It copies to the clipboard before printing
//!   anything, and `arboard` fails on a headless runner — so a `get` assertion
//!   would fail in CI for reasons unrelated to sk2. `verify` proves the same
//!   decryption path without touching the clipboard.
//! * **The vault path is passed as `--vault`, never `SK2_VAULT`.** Setting an
//!   environment variable in a forked child means allocating after `fork()` in a
//!   multi-threaded process, which can deadlock. Building argv before forking
//!   avoids that entirely.

#![cfg(unix)]

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_simpleKeychain2");
const MASTER: &str = "correct horse battery staple\n";
const TIMEOUT: Duration = Duration::from_secs(60);

// --- scratch vault ------------------------------------------------------------

/// A private directory removed when the test ends, however it ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sk2-it-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Scratch(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }

    fn vault(&self) -> String {
        self.path("vault.db")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// --- PTY session --------------------------------------------------------------

struct Outcome {
    code: i32,
    text: String,
}

impl Outcome {
    #[track_caller]
    fn assert_ok(&self) -> &Self {
        assert_eq!(
            self.code, 0,
            "expected success, got {}\n{}",
            self.code, self.text
        );
        self
    }

    #[track_caller]
    fn assert_failed(&self) -> &Self {
        assert_ne!(
            self.code, 0,
            "expected failure but it succeeded\n{}",
            self.text
        );
        self
    }

    #[track_caller]
    fn assert_says(&self, needle: &str) -> &Self {
        assert!(
            self.text.to_lowercase().contains(&needle.to_lowercase()),
            "expected output to contain {needle:?}\n--- actual ---\n{}",
            self.text
        );
        self
    }

    #[track_caller]
    fn assert_silent_about(&self, needle: &str) -> &Self {
        assert!(
            !self.text.to_lowercase().contains(&needle.to_lowercase()),
            "expected output NOT to contain {needle:?}\n--- actual ---\n{}",
            self.text
        );
        self
    }
}

struct Session {
    fd: i32,
    pid: libc::pid_t,
    output: String,
    cursor: usize,
}

/// Spawn `sk2 <args>` attached to a fresh PTY.
fn sk2(args: &[&str]) -> Session {
    spawn_at(BIN, args)
}

fn spawn_at(binary: &str, args: &[&str]) -> Session {
    // Build argv fully before forking: the child must not allocate.
    let argv_owned: Vec<CString> = std::iter::once(binary)
        .chain(args.iter().copied())
        .map(|a| CString::new(a).expect("argv contains a NUL"))
        .collect();
    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    let mut master_fd: libc::c_int = -1;
    // SAFETY: forkpty writes the master descriptor into `master_fd`. In the child
    // (pid == 0) we immediately execv with pointers prepared above and never return;
    // on failure we _exit without unwinding.
    // The termios/winsize pointers are null_mut, not null: macOS declares them
    // `*mut` where Linux declares `*const`, and only `*mut` coerces to both.
    let pid = unsafe {
        libc::forkpty(
            &mut master_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert!(pid >= 0, "forkpty failed");

    if pid == 0 {
        unsafe {
            libc::execv(argv_owned[0].as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }

    Session {
        fd: master_fd,
        pid,
        output: String::new(),
        cursor: 0,
    }
}

impl Session {
    /// Read whatever is available. Returns false at EOF.
    fn pump(&mut self, budget: Duration) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: single valid pollfd, count matches.
        let ready = unsafe { libc::poll(&mut pfd, 1, budget.as_millis() as libc::c_int) };
        if ready <= 0 {
            return true; // idle, not finished
        }
        let mut buf = [0u8; 4096];
        // SAFETY: buf is valid for len bytes.
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return false; // EOF (the child closed the slave side)
        }
        self.output
            .push_str(&String::from_utf8_lossy(&buf[..n as usize]));
        true
    }

    /// Wait for `needle` in output not yet consumed, then advance past it. Searching
    /// from a cursor rather than the whole buffer keeps repeated prompts in order —
    /// "Master password" and "New master password" both contain the former.
    #[track_caller]
    fn expect(mut self, needle: &str) -> Self {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let hay = strip_ansi(&self.output).to_lowercase();
            let from = self.cursor.min(hay.len());
            if let Some(at) = hay[from..].find(&needle.to_lowercase()) {
                self.cursor = from + at + needle.len();
                return self;
            }
            if Instant::now() >= deadline || !self.pump(Duration::from_millis(200)) {
                panic!(
                    "timed out waiting for {needle:?}\n--- output so far ---\n{}",
                    strip_ansi(&self.output)
                );
            }
        }
    }

    fn send(self, line: &str) -> Self {
        let bytes = line.as_bytes();
        // SAFETY: writing `bytes.len()` bytes from a valid slice to an open fd.
        let n = unsafe { libc::write(self.fd, bytes.as_ptr().cast(), bytes.len()) };
        assert!(n > 0, "write to pty failed");
        self
    }

    /// Answer a prompt: wait for it, then send.
    #[track_caller]
    fn answer(self, prompt: &str, line: &str) -> Self {
        self.expect(prompt).send(line)
    }

    fn finish(mut self) -> Outcome {
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline && self.pump(Duration::from_millis(200)) {}

        let mut status: libc::c_int = 0;
        // SAFETY: waiting on our own child.
        unsafe { libc::waitpid(self.pid, &mut status, 0) };
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        // SAFETY: fd is open and owned by this session.
        unsafe { libc::close(self.fd) };

        Outcome {
            code,
            text: strip_ansi(&self.output),
        }
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for t in chars.by_ref() {
                    if t.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else if c != '\r' {
            out.push(c);
        }
    }
    out
}

// --- helpers ------------------------------------------------------------------

fn init_vault(vault: &str) {
    sk2(&["--vault", vault, "init"])
        .answer("set master password", MASTER)
        .answer("confirm master password", MASTER)
        .finish()
        .assert_ok()
        .assert_says("Vault initialized");
}

fn add(vault: &str, service: &str, user: &str, pass: &str) {
    sk2(&["--vault", vault, "add", service])
        .answer("master password", MASTER)
        .answer("username", &format!("{user}\n"))
        .answer("password", &format!("{pass}\n"))
        .finish()
        .assert_ok()
        .assert_says(&format!("Credential stored for '{service}'"));
}

fn verify(vault: &str, master: &str) -> Outcome {
    sk2(&["--vault", vault, "verify"])
        .answer("master password", master)
        .finish()
}

// --- tests --------------------------------------------------------------------

#[test]
fn init_add_list_and_verify() {
    let s = Scratch::new("basic");
    let v = s.vault();

    init_vault(&v);
    add(&v, "github", "octocat", "gh-pass-123");
    add(&v, "gmail", "me@example.com", "gm@il!pw");

    sk2(&["--vault", &v, "list"])
        .answer("master password", MASTER)
        .finish()
        .assert_ok()
        .assert_says("github")
        .assert_says("gmail")
        .assert_says("2 credentials");

    verify(&v, MASTER)
        .assert_ok()
        .assert_says("All 2 credentials verified");
}

#[test]
fn wrong_master_password_is_rejected() {
    let s = Scratch::new("wrongpw");
    let v = s.vault();

    init_vault(&v);
    add(&v, "github", "octocat", "gh-pass-123");

    verify(&v, "not the right password\n")
        .assert_failed()
        .assert_says("Wrong master password");
}

#[test]
fn init_refuses_to_clobber_an_existing_vault() {
    let s = Scratch::new("reinit");
    let v = s.vault();

    init_vault(&v);
    sk2(&["--vault", &v, "init"])
        .finish()
        .assert_failed()
        .assert_says("already initialized");
}

/// `edit` shows the stored username in brackets, which proves the value survived a
/// full encrypt/store/decrypt cycle without needing the clipboard.
#[test]
fn edit_shows_current_values_and_updates_them() {
    let s = Scratch::new("edit");
    let v = s.vault();

    init_vault(&v);
    add(&v, "github", "octocat", "gh-pass-123");

    sk2(&["--vault", &v, "edit", "github"])
        .answer("master password", MASTER)
        .expect("username [octocat]")
        .send("\n")
        .answer("new password", "rotated-pw-456\n")
        .finish()
        .assert_ok()
        .assert_says("updated");

    verify(&v, MASTER).assert_ok().assert_says("✓ github");
}

#[test]
fn rename_moves_the_credential() {
    let s = Scratch::new("rename");
    let v = s.vault();

    init_vault(&v);
    add(&v, "github", "octocat", "gh-pass-123");

    sk2(&["--vault", &v, "rename", "github", "gh"])
        .answer("master password", MASTER)
        .finish()
        .assert_ok();

    // Re-encrypted under the new service name as AAD, so it must still verify.
    verify(&v, MASTER)
        .assert_ok()
        .assert_says("✓ gh")
        .assert_silent_about("✓ github");
}

#[test]
fn change_password_rekeys_every_credential() {
    let s = Scratch::new("changepw");
    let v = s.vault();
    let new_master = "an entirely different master password\n";

    init_vault(&v);
    add(&v, "github", "octocat", "gh-pass-123");
    add(&v, "gmail", "me@example.com", "gm@il!pw");

    sk2(&["--vault", &v, "change-password"])
        .answer("master password", MASTER)
        .answer("new master password", new_master)
        .answer("confirm new master password", new_master)
        .finish()
        .assert_ok()
        .assert_says("Master password changed");

    verify(&v, new_master)
        .assert_ok()
        .assert_says("All 2 credentials verified");
    verify(&v, MASTER)
        .assert_failed()
        .assert_says("Wrong master password");
}

/// F7b: an invalid flag combination must be rejected before the master password is
/// ever requested. The assertion that matters is the *absence* of the prompt.
#[test]
fn invalid_flags_are_rejected_before_any_prompt() {
    let s = Scratch::new("flags");
    let v = s.vault();

    init_vault(&v);

    sk2(&["--vault", &v, "add", "svc", "-l", "20"])
        .finish()
        .assert_failed()
        .assert_says("--length requires --generate")
        .assert_silent_about("Username");

    sk2(&["--vault", &v, "add", "svc", "-c", "hex"])
        .finish()
        .assert_failed()
        .assert_says("--charset requires --generate")
        .assert_silent_about("Username");
}

/// `generate` is the one command that needs neither a vault nor a master password.
///
/// F11: the clipboard is an enhancement, not a requirement — the password is already
/// printed, so a clipboard failure warns and the command still exits 0. That is what
/// makes the exit code assertable here on headless and desktop machines alike (it
/// previously exited 1 on any runner without a display, breaking `set -e` scripts).
#[test]
fn generate_needs_no_vault() {
    let s = Scratch::new("generate");
    let missing = s.path("does-not-exist.db");

    sk2(&["--vault", &missing, "generate", "-l", "32", "-c", "hex"])
        .finish()
        .assert_ok()
        .assert_silent_about("Master password")
        .assert_says("Password:");

    assert!(
        !Path::new(&missing).exists(),
        "generate must not create a vault"
    );
}

/// F11: `get --print` writes the bare secret to stdout with a warning on stderr and
/// skips the clipboard entirely. Skipping the clipboard is also what makes `get`
/// assertable in this suite at all — the clipboard path fails on a headless runner,
/// so no `get` invocation had ever been end-to-end tested before this flag existed.
#[test]
fn get_print_displays_the_password() {
    let s = Scratch::new("getprint");
    let v = s.vault();

    init_vault(&v);
    add(&v, "github", "octocat", "gh-pass-123");

    sk2(&["--vault", &v, "get", "github", "--print"])
        .answer("master password", MASTER)
        .finish()
        .assert_ok()
        .assert_says("gh-pass-123")
        .assert_says("scrollback") // the stern stored-password warning fired
        .assert_silent_about("copied to clipboard");

    // With --username the username is printed instead, without the password —
    // and without the password warning, since usernames are shown in plaintext
    // by a normal `get` anyway.
    sk2(&["--vault", &v, "get", "github", "--username", "--print"])
        .answer("master password", MASTER)
        .finish()
        .assert_ok()
        .assert_says("octocat")
        .assert_silent_about("gh-pass-123")
        .assert_silent_about("scrollback");
}

#[cfg(all(feature = "export", feature = "import"))]
#[test]
fn sk2b_backup_round_trips_through_the_cli() {
    let s = Scratch::new("sk2b");
    let source = s.vault();
    let restored = s.path("restored.db");
    let backup = s.path("backup.sk2backup");
    let passphrase = "a backup passphrase\n";

    init_vault(&source);
    add(&source, "github", "octocat", "gh-pass-123");
    add(&source, "gmail", "me@example.com", "gm@il!pw");

    sk2(&["--vault", &source, "export", "-o", &backup])
        .answer("master password", MASTER)
        .answer("type 'yes'", "yes\n")
        .answer("backup passphrase", passphrase)
        .answer("confirm backup passphrase", passphrase)
        .finish()
        .assert_ok()
        .assert_says("Exported 2 credential(s)");

    assert!(Path::new(&backup).exists(), "backup file was not written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "backup must be owner-only, got {mode:o}");
    }

    // Restore into a brand-new vault with a different master password: the backup
    // is sealed with its own passphrase and must not depend on the original key.
    let other_master = "a different master password entirely\n";
    sk2(&["--vault", &restored, "init"])
        .answer("set master password", other_master)
        .answer("confirm master password", other_master)
        .finish()
        .assert_ok();

    sk2(&["--vault", &restored, "import", &backup])
        .answer("master password", other_master)
        .answer("type 'yes'", "yes\n")
        .answer("backup passphrase", passphrase)
        .finish()
        .assert_ok()
        .assert_says("Imported 2 credential(s)");

    verify(&restored, other_master)
        .assert_ok()
        .assert_says("All 2 credentials verified");
}

#[cfg(all(feature = "export", feature = "import"))]
#[test]
fn import_rejects_the_wrong_backup_passphrase() {
    let s = Scratch::new("sk2b-wrongpass");
    let source = s.vault();
    let backup = s.path("backup.sk2backup");

    init_vault(&source);
    add(&source, "github", "octocat", "gh-pass-123");

    sk2(&["--vault", &source, "export", "-o", &backup])
        .answer("master password", MASTER)
        .answer("type 'yes'", "yes\n")
        .answer("backup passphrase", "right passphrase\n")
        .answer("confirm backup passphrase", "right passphrase\n")
        .finish()
        .assert_ok();

    sk2(&["--vault", &source, "import", &backup])
        .answer("master password", MASTER)
        .answer("type 'yes'", "yes\n")
        .answer("backup passphrase", "wrong passphrase\n")
        .finish()
        .assert_failed()
        .assert_says("decryption failed");
}

/// Cross-version upgrade check. Skipped unless `SK2_OLD_BINARY` points at a build of
/// a previous release — building an old tag is far too heavy for `cargo test`.
///
///   git worktree add /tmp/sk2-old v1.0.0
///   (cd /tmp/sk2-old && cargo build --release)
///   SK2_OLD_BINARY=/tmp/sk2-old/target/release/simpleKeychain2 cargo test --test cli
///
/// Guards the property that matters most on upgrade: a vault created by an older
/// release must still open, with the same master password, under the current build.
#[test]
fn vault_from_an_older_release_still_opens() {
    let Some(old) = std::env::var_os("SK2_OLD_BINARY") else {
        eprintln!(
            "SKIPPED: vault_from_an_older_release_still_opens — set SK2_OLD_BINARY to \
             a previous release build to run it (see the doc comment)."
        );
        return;
    };
    let old = old.to_string_lossy().into_owned();
    assert!(
        Path::new(&old).exists(),
        "SK2_OLD_BINARY does not exist: {old}"
    );

    let s = Scratch::new("upgrade");
    let v = s.vault();

    // Create the vault with the OLD binary.
    spawn_at(&old, &["--vault", &v, "init"])
        .answer("set master password", MASTER)
        .answer("confirm master password", MASTER)
        .finish()
        .assert_ok();

    spawn_at(&old, &["--vault", &v, "add", "github"])
        .answer("master password", MASTER)
        .answer("username", "octocat\n")
        .answer("password", "gh-pass-123\n")
        .finish()
        .assert_ok();

    // Open it with the CURRENT binary: same password, every row must decrypt.
    verify(&v, MASTER)
        .assert_ok()
        .assert_says("All 1 credentials verified");

    // And the current build must be able to re-key a vault it did not create.
    let new_master = "rotated after upgrading\n";
    sk2(&["--vault", &v, "change-password"])
        .answer("master password", MASTER)
        .answer("new master password", new_master)
        .answer("confirm new master password", new_master)
        .finish()
        .assert_ok();

    verify(&v, new_master).assert_ok().assert_says("✓ github");
}
