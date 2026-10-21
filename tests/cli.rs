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
//! * **`get`'s clipboard path is not asserted on.** It copies to the clipboard
//!   before printing anything, and `arboard` fails on a headless runner — so that
//!   assertion would fail in CI for reasons unrelated to sk2. `verify` proves the
//!   same decryption path without touching the clipboard. `get --print` is a
//!   different matter: it skips the clipboard entirely, so it *is* asserted
//!   directly (`get_print_displays_the_password`). Since F11 that is the one `get`
//!   invocation this suite can drive end to end.
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
        // Tests run in parallel, and two sharing a name would share a directory —
        // one's cleanup deleting the other's vault mid-test. Catch that at the source.
        static USED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let mut used = USED.lock().unwrap();
        assert!(
            !used.iter().any(|n| n == name),
            "two tests use Scratch::new({name:?}); names must be unique"
        );
        used.push(name.to_string());
        drop(used);
        let dir = std::env::temp_dir().join(format!("sk2-it-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        // Set explicitly rather than trusting the runner's umask: sk2 refuses a vault
        // in a directory other users can write (S3).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("make scratch dir private");
        }
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
    /// Set by `finish`. Until then `Drop` owns the child.
    reaped: bool,
}

/// A test that panics mid-session never reaches `finish`, and its child would sit
/// at a prompt on a dead terminal indefinitely — eight such orphans were found
/// still running on 2026-10-21. Kill and reap it instead.
impl Drop for Session {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: signalling, reaping and closing what this session owns.
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
                libc::waitpid(self.pid, std::ptr::null_mut(), 0);
                libc::close(self.fd);
            }
        }
    }
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
        reaped: false,
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
        let mut eof = false;
        while Instant::now() < deadline {
            if !self.pump(Duration::from_millis(200)) {
                eof = true;
                break;
            }
        }

        // A child that never closed the terminal by the deadline is almost always
        // sitting at a prompt the test did not expect — a blocking waitpid would hang
        // the suite on it forever instead of failing. Kill it, and say so. Only on a
        // timeout: after EOF the child is exiting, just perhaps not yet reaped, and a
        // WNOHANG probe there would kill a process on its way to exit 0.
        if !eof {
            // SAFETY: signalling our own child.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
            self.output
                .push_str("\n[harness: child still running at the deadline; killed]\n");
        }
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
        self.reaped = true;

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
        // Shown before the confirmation, as `change-password` does (S5).
        .expect("strength:")
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

/// S3: a vault file someone else could read — here pre-created `0666`, as another
/// user could do in a shared directory — is refused before any prompt, and left
/// exactly as it was rather than initialized into.
#[test]
fn init_refuses_a_vault_file_other_users_can_access() {
    use std::os::unix::fs::PermissionsExt;
    let s = Scratch::new("exposed");
    let v = s.vault();
    std::fs::write(&v, b"").unwrap();
    std::fs::set_permissions(&v, std::fs::Permissions::from_mode(0o666)).unwrap();

    sk2(&["--vault", &v, "init"])
        .finish()
        .assert_failed()
        .assert_says("accessible to other users")
        .assert_silent_about("Master password");

    let meta = std::fs::metadata(&v).unwrap();
    assert_eq!(meta.len(), 0, "the file must not have been initialized");
    assert_eq!(meta.permissions().mode() & 0o777, 0o666);
}

/// The upgrade path for a vault S3 refuses: every fix the error offers is a
/// permission change or a move, the vault is untouched by the refusal, and after
/// the fix it opens with the same master password and every credential intact.
/// The `chmod` commands are taken from the error text and run through a real
/// shell, in a directory with a space in its name, so the quoting is tested too.
#[test]
fn a_refused_vault_opens_again_after_the_suggested_fix() {
    use std::os::unix::fs::PermissionsExt;
    let set_mode = |p: &std::path::Path, m| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
    };
    // The single command the error tells the user to run, as printed.
    let suggested_fix = |out: &Outcome| -> String {
        let mut lines = out.text.lines();
        lines
            .find(|l| l.contains("To fix:"))
            .expect("no fix offered");
        lines.next().expect("fix line").trim().to_string()
    };
    let run_in_shell = |cmd: &str| {
        let ok = std::process::Command::new("sh")
            .args(["-c", cmd])
            .status()
            .expect("run sh")
            .success();
        assert!(ok, "suggested fix failed: {cmd}");
    };
    let get_print = |v: &str| {
        sk2(&["--vault", v, "get", "github", "--print"])
            .answer("master password", MASTER)
            .finish()
            .assert_ok()
            .assert_says("gh-pass-123");
    };

    let s = Scratch::new("refused-then-fixed");
    let dir = s.0.join("my vaults");
    std::fs::create_dir(&dir).unwrap();
    set_mode(&dir, 0o700);
    let path = dir.join("vault.db");
    let v = path.to_string_lossy().into_owned();
    init_vault(&v);
    add(&v, "github", "octocat", "gh-pass-123");
    let before = std::fs::read(&path).unwrap();

    // 1. A loose file mode — as left by a download, a sync client, or a restore.
    set_mode(&path, 0o644);
    let out = sk2(&["--vault", &v, "list"]).finish();
    out.assert_failed()
        .assert_says("has not been changed")
        .assert_silent_about("Master password");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "refusal touched the vault"
    );
    let fix = suggested_fix(&out);
    assert!(fix.starts_with("chmod 600 '"), "path not quoted: {fix}");
    run_in_shell(&fix);
    get_print(&v);

    // 2. A group-writable directory — what a umask of 002 gives a user's own
    // directories on Fedora and RHEL.
    set_mode(&dir, 0o775);
    let out = sk2(&["--vault", &v, "list"]).finish();
    out.assert_failed()
        .assert_says("has not opened or changed anything")
        .assert_silent_about("Master password");
    let fix = suggested_fix(&out);
    assert!(fix.starts_with("chmod go-w '"), "path not quoted: {fix}");
    run_in_shell(&fix);
    get_print(&v);

    // 3. A move, the fix for a directory that is not the user's to tighten. The
    // vault's encryption does not depend on its path.
    let moved = s.path("moved.db");
    std::fs::rename(&path, &moved).unwrap();
    get_print(&moved);
    verify(&moved, MASTER).assert_ok();
}

/// S6: while sk2 waits at a prompt — the state in which it holds secrets — another
/// process running as the same user cannot read its memory or environment through
/// `/proc`, and it cannot dump core. The test process plays that other process. It
/// is sk2's parent, which Yama's default `ptrace_scope` 1 would still allow, so a
/// refusal here comes from sk2 itself.
#[cfg(target_os = "linux")]
#[test]
fn a_waiting_sk2_cannot_be_read_by_other_processes() {
    let s = Scratch::new("hardened");
    let v = s.vault();

    let session = sk2(&["--vault", &v, "init"]).expect("set master password");
    let proc_dir = format!("/proc/{}", session.pid);

    for file in ["mem", "environ"] {
        let err = std::fs::File::open(format!("{proc_dir}/{file}"))
            .expect_err(&format!("/proc/<pid>/{file} must not be readable"));
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "{file}: {err}"
        );
    }

    let limits = std::fs::read_to_string(format!("{proc_dir}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .expect("core limit line");
    let fields: Vec<&str> = core.split_whitespace().collect();
    assert_eq!(
        &fields[4..6],
        ["0", "0"],
        "soft and hard core limit: {core}"
    );

    session
        .send(MASTER)
        .answer("confirm master password", MASTER)
        .finish()
        .assert_ok()
        .assert_says("Vault initialized");
}

/// `get --print --notes` is the only way to read notes without a clipboard — the
/// headless case `--print` exists for — so it is tested here, where the plain
/// `get` display cannot be. The notes come out bare on stdout with the stern
/// warning; the password does not appear; asking for two values at once is refused
/// before the master password prompt.
#[test]
fn get_print_notes_displays_the_notes() {
    let s = Scratch::new("printnotes");
    let v = s.vault();
    init_vault(&v);
    sk2(&["--vault", &v, "add", "bank", "--notes"])
        .answer("master password", MASTER)
        .answer("username", "me\n")
        .answer("password", "bank-pass-123\n")
        .answer("notes", "recovery: 1111-2222\n")
        .finish()
        .assert_ok();
    add(&v, "plain", "me", "plain-pass-123");

    sk2(&["--vault", &v, "get", "bank", "--print", "--notes"])
        .answer("master password", MASTER)
        .finish()
        .assert_ok()
        .assert_says("recovery: 1111-2222")
        .assert_says("Printing stored notes")
        .assert_silent_about("bank-pass-123")
        .assert_silent_about("copied to clipboard");

    sk2(&["--vault", &v, "get", "plain", "--print", "--notes"])
        .answer("master password", MASTER)
        .finish()
        .assert_failed()
        .assert_says("No notes stored for 'plain'")
        .assert_silent_about("plain-pass-123");

    sk2(&[
        "--vault",
        &v,
        "get",
        "bank",
        "--print",
        "--notes",
        "--username",
    ])
    .finish()
    .assert_failed()
    .assert_says("not both")
    .assert_silent_about("Master password");
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

/// The hidden flag behind shell completion. It fires on every Tab press, so all
/// three of its rules are asserted here: no prompt, no output but the names, and
/// no side effects on the filesystem.
#[cfg(feature = "completion")]
#[test]
fn list_services_backs_shell_completion() {
    let s = Scratch::new("listservices");
    let v = s.vault();

    init_vault(&v);
    add(&v, "github", "octocat", "gh-pass-123");
    add(&v, "gmail", "me@example.com", "gm@il!pw");

    let out = sk2(&["--vault", &v, "--list-services"]).finish();
    out.assert_ok()
        .assert_says("github")
        .assert_says("gmail")
        // The whole point: usable without unlocking the vault.
        .assert_silent_about("Master password")
        // Only names. A completion menu must not show usernames or secrets.
        .assert_silent_about("octocat")
        .assert_silent_about("gh-pass-123");

    // One name per line and nothing else — the completion scripts split on \n.
    let lines: Vec<&str> = out
        .text
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        lines,
        vec!["github", "gmail"],
        "expected exactly the service names, sorted, one per line"
    );
}

/// A Tab press on a machine with no vault must stay silent *and* leave the disk
/// alone. `Connection::open` would have created the database file, so without the
/// read-only open this would quietly conjure a vault the first time anyone pressed
/// Tab.
#[cfg(feature = "completion")]
#[test]
fn list_services_creates_nothing_when_there_is_no_vault() {
    let s = Scratch::new("listservices-novault");
    let missing = s.path("does-not-exist.db");

    sk2(&["--vault", &missing, "--list-services"])
        .finish()
        .assert_ok()
        .assert_silent_about("Master password")
        .assert_silent_about("error");

    assert!(
        !Path::new(&missing).exists(),
        "completion must never create a vault"
    );
}

/// `completions <shell>` emits a script for every shell the spec promises, without
/// a vault and without a master password.
#[cfg(feature = "completion")]
#[test]
fn completion_scripts_are_emitted_for_every_shell() {
    let s = Scratch::new("completions");
    let missing = s.path("does-not-exist.db");

    for (shell, needle) in [
        ("bash", "complete -F _sk2 sk2"),
        ("zsh", "#compdef sk2"),
        ("fish", "complete -c sk2"),
        ("powershell", "Register-ArgumentCompleter"),
    ] {
        sk2(&["--vault", &missing, "completions", shell])
            .finish()
            .assert_ok()
            .assert_says(needle)
            .assert_says("--list-services")
            // The prompt text, with its colon, rather than the bare phrase: every
            // script's header comment says it "never prompts for a master
            // password", which would match a looser check.
            .assert_silent_about("Master password:");
    }

    assert!(
        !Path::new(&missing).exists(),
        "emitting a completion script must not create a vault"
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
