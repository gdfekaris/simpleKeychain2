mod constants;
mod crypto;
mod db;
#[cfg(feature = "export")]
mod export;
#[cfg(feature = "import")]
mod import;
mod ui;
mod vault;

use arboard::Clipboard;
use clap::builder::styling::{AnsiColor, Styles};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().bold())
    .usage(AnsiColor::Yellow.on_default().bold())
    .literal(AnsiColor::Yellow.on_default().bold())
    .placeholder(AnsiColor::White.on_default())
    .valid(AnsiColor::Green.on_default().bold())
    .invalid(AnsiColor::Red.on_default().bold())
    .error(AnsiColor::Red.on_default().bold());
use rusqlite::Connection;
use std::process;
use std::thread;
use std::time::Duration;
use zeroize::Zeroizing;

use constants::*;

fn vault_path() -> std::path::PathBuf {
    let dir = dirs::home_dir()
        .expect("Could not determine home directory")
        .join(".sk2");
    std::fs::create_dir_all(&dir).expect("Failed to create vault directory");
    dir.join("vault.db")
}

#[derive(Parser)]
#[command(name = "sk2", about = "A local-only CLI password manager", styles = STYLES)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Internal: clear clipboard after N seconds (used by spawned child)
    #[arg(long = "clear-clipboard", hide = true)]
    clear_clipboard: Option<u64>,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new vault (set master password)
    Init,
    /// Add or update a credential
    ///
    /// (use --generate for a random password)
    Add {
        /// The service name (e.g. "github", "gmail")
        service: String,
        /// Generate a random password instead of prompting for one
        #[arg(short, long)]
        generate: bool,
        /// Length of the generated password (default: 16, range: 4–64)
        #[arg(short, long, default_value_t = 16)]
        length: usize,
        /// Character set to use when generating a password (requires --generate)
        #[arg(short, long, default_value = "default")]
        charset: crypto::Charset,
        /// Prompt for notes after the password step (recovery codes, security questions, etc.)
        #[arg(long)]
        notes: bool,
        /// Optional URL for the service
        #[arg(long)]
        url: Option<String>,
    },
    /// Retrieve a credential by service name
    Get {
        /// The service name to look up
        service: String,
    },
    /// Delete a credential by service name
    Delete {
        /// The service name to delete
        service: String,
    },
    /// List all stored service names
    List {
        /// Show only credentials not updated within the threshold
        #[arg(long)]
        stale: bool,
        /// Staleness threshold in days for --stale (default: 90)
        #[arg(long, default_value_t = 90)]
        days: u64,
    },
    /// Edit an existing credential
    Edit {
        /// The service name to edit
        service: String,
        /// Edit only the username
        #[arg(long)]
        username: bool,
        /// Edit only the password
        #[arg(long)]
        password: bool,
        /// Edit only the notes
        #[arg(long)]
        notes: bool,
        /// Edit only the URL
        #[arg(long)]
        url: bool,
    },
    /// Rename a stored service
    Rename {
        /// The current service name
        old_service: String,
        /// The new service name
        new_service: String,
    },
    /// Change the master password
    ChangePassword,
    /// Export all credentials as a GPG-encrypted CSV file
    #[cfg(feature = "export")]
    Export {
        /// Output file path
        #[arg(short, long, default_value = "sk2-export.csv.gpg")]
        output: String,
    },
    /// Import credentials from a GPG-encrypted CSV file
    #[cfg(feature = "import")]
    Import {
        /// Path to the GPG-encrypted CSV file
        file: String,
    },
}

// --- Main ---

fn run(cli: Cli) -> Result<(), String> {
    let command = cli.command.ok_or("No command provided. Run with --help for usage.")?;

    let db_path = vault_path();
    let conn = Connection::open(&db_path).expect("Failed to open database");
    vault::restrict_db_permissions(&db_path);
    db::init_db(&conn);

    match command {
        Command::Init => {
            vault::init_vault(&conn)?;
        }

        Command::Add { service, generate, length, charset, notes, url } => {
            let key = vault::unlock_vault(&conn)?;
            let username = vault::prompt("Username: ");

            let password = if generate {
                if !(4..=64).contains(&length) {
                    return Err("Password length must be between 4 and 64.".into());
                }
                let alphabet_size = match charset {
                    crypto::Charset::Default      => 74.0_f64,
                    crypto::Charset::Alphanumeric => 62.0,
                    crypto::Charset::Websafe      => 66.0,
                    crypto::Charset::Hex          => 16.0,
                    crypto::Charset::Dna          => 4.0,
                };
                let entropy_bits = length as f64 * alphabet_size.log2();
                if entropy_bits < 64.0 {
                    ui::warning(&format!(
                        "Low entropy: ~{:.0} bits. Consider increasing --length.",
                        entropy_bits
                    ));
                }
                crypto::generate_password(length, &charset)
            } else {
                if length != 16 {
                    return Err("--length requires --generate.".into());
                }
                if !matches!(charset, crypto::Charset::Default) {
                    return Err("--charset requires --generate.".into());
                }
                ui::service_password_prompt("Password: ");
                let p = Zeroizing::new(
                    rpassword::read_password_from_tty(None)
                        .expect("Failed to read password"),
                );
                if p.is_empty() {
                    return Err("Password cannot be empty.".into());
                }
                p
            };

            let notes_value = if notes { vault::plain_prompt("Notes: ") } else { String::new() };

            db::add_credential(&conn, &key, &service, &username, &password,
                &notes_value,
                url.as_deref().unwrap_or(""));
            ui::success(&format!("Credential stored for '{service}'."));
        }

        Command::Get { service } => {
            let key = vault::unlock_vault(&conn)?;
            match db::get_credential(&conn, &key, &service) {
                Some((username, password, notes, url, updated_at)) => {
                    let password = Zeroizing::new(password);
                    let mut clipboard = Clipboard::new()
                        .map_err(|e| format!("Failed to access clipboard: {e}"))?;
                    clipboard.set_text(&*password)
                        .map_err(|e| format!("Failed to copy to clipboard: {e}"))?;

                    // Spawn a detached child process to clear the clipboard after the timeout.
                    match std::env::current_exe() {
                        Ok(exe) => {
                            let result = process::Command::new(exe)
                                .arg("--clear-clipboard")
                                .arg(CLIPBOARD_CLEAR_SECONDS.to_string())
                                .stdin(process::Stdio::null())
                                .stdout(process::Stdio::null())
                                .stderr(process::Stdio::null())
                                .spawn();
                            if let Err(e) = result {
                                ui::warning(&format!("Could not spawn clipboard-clear process: {e}"));
                            }
                        }
                        Err(e) => {
                            ui::warning(&format!("Could not determine executable path: {e}"));
                        }
                    }

                    ui::get_service(&service);
                    ui::get_username(&username);
                    if !url.is_empty() {
                        ui::get_url(&url);
                    }
                    if !notes.is_empty() {
                        ui::get_notes(&notes);
                    }
                    ui::get_updated_at(updated_at);
                    ui::clipboard_notice(CLIPBOARD_CLEAR_SECONDS);
                    // Brief pause so the clipboard manager can grab the contents
                    // before the process exits (needed on Linux/Wayland).
                    thread::sleep(Duration::from_millis(100));
                }
                None => {
                    return Err(format!("No credential found for '{service}'."));
                }
            }
        }

        Command::Delete { service } => {
            vault::unlock_vault(&conn)?;
            if db::delete_credential(&conn, &service) {
                ui::success(&format!("Credential for '{service}' deleted."));
            } else {
                return Err(format!("No credential found for '{service}'."));
            }
        }

        Command::List { stale, days } => {
            vault::unlock_vault(&conn)?;
            if stale {
                let entries = db::list_services_with_timestamps(&conn);
                if entries.is_empty() {
                    ui::muted("No credentials stored.");
                } else {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs() as i64;
                    let threshold = (days * 86400) as i64;
                    let stale_entries: Vec<_> = entries.iter().filter(|(_, ts)| {
                        ts.is_none_or(|t| now - t >= threshold)
                    }).collect();
                    if stale_entries.is_empty() {
                        ui::muted(&format!("No credentials older than {days} days."));
                    } else {
                        ui::header(&format!("Credentials not updated in {days}+ days:"));
                        for (service, ts) in &stale_entries {
                            let age = ts.map_or("unknown age".to_string(), |t| {
                                let d = (now - t).max(0) / 86400;
                                match d {
                                    0 => "today".to_string(),
                                    1 => "1 day ago".to_string(),
                                    n => format!("{n} days ago"),
                                }
                            });
                            ui::list_item_stale(service, &age);
                        }
                    }
                }
            } else {
                let services = db::list_services(&conn);
                if services.is_empty() {
                    ui::muted("No credentials stored.");
                } else {
                    ui::header("Stored credentials:");
                    for s in &services {
                        ui::list_item(s);
                    }
                }
            }
        }

        Command::Edit { service, username: edit_username, password: edit_password, notes: edit_notes, url: edit_url } => {
            let key = vault::unlock_vault(&conn)?;

            let (current_username, current_password, current_notes, current_url, _) =
                db::get_credential(&conn, &key, &service)
                    .ok_or_else(|| format!("No credential found for '{service}'."))?;
            let current_password = Zeroizing::new(current_password);

            let neither = !edit_username && !edit_password && !edit_notes && !edit_url;
            let prompt_username = edit_username || neither;
            let prompt_password = edit_password || neither;

            let new_username = if prompt_username {
                let input = vault::prompt(&format!("Username [{}]: ", current_username));
                if input.is_empty() { current_username } else { input }
            } else {
                current_username
            };

            let mut password_was_changed = false;
            let new_password: Zeroizing<String> = if prompt_password {
                ui::service_password_prompt("New password (leave blank to keep current): ");
                let input = Zeroizing::new(
                    rpassword::read_password_from_tty(None)
                        .expect("Failed to read password"),
                );
                if input.is_empty() {
                    current_password
                } else {
                    password_was_changed = true;
                    input
                }
            } else {
                current_password
            };

            let new_notes = if edit_notes {
                let display = if current_notes.is_empty() { "(none)".to_string() } else { current_notes.clone() };
                let input = vault::plain_prompt(&format!("Notes [{}]: ", display));
                if input.is_empty() { current_notes } else { input }
            } else {
                current_notes
            };

            let new_url = if edit_url {
                let display = if current_url.is_empty() { "(none)".to_string() } else { current_url.clone() };
                let input = vault::plain_prompt(&format!("URL [{}]: ", display));
                if input.is_empty() { current_url } else { input }
            } else {
                current_url
            };

            if !db::update_credential(&conn, &key, &service, &new_username, &new_password, &new_notes, &new_url, password_was_changed) {
                return Err(format!("No credential found for '{service}'."));
            }
            ui::success(&format!("Credential for '{service}' updated."));
        }

        Command::Rename { old_service, new_service } => {
            let key = vault::unlock_vault(&conn)?;
            db::rename_credential(&conn, &key, &old_service, &new_service)?;
            ui::success(&format!("Renamed '{old_service}' to '{new_service}'."));
        }

        Command::ChangePassword => {
            vault::change_password(&conn)?;
        }

        #[cfg(feature = "export")]
        Command::Export { output } => {
            let key = vault::unlock_vault(&conn)?;
            export::export_credentials(&conn, &key, &output)?;
        }

        #[cfg(feature = "import")]
        Command::Import { file } => {
            let key = vault::unlock_vault(&conn)?;
            import::import_credentials(&conn, &key, &file)?;
        }
    }

    Ok(())
}

fn main() -> process::ExitCode {
    let banner = ui::colored_banner();
    let version: &str = format!("\n{banner}\n  v{}", env!("CARGO_PKG_VERSION")).leak();

    let matches = Cli::command()
        .before_help(banner)
        .version(version)
        .get_matches();

    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    // Hidden mode: clear clipboard after a delay, then exit.
    if let Some(seconds) = cli.clear_clipboard {
        thread::sleep(Duration::from_secs(seconds));
        if let Ok(mut clipboard) = Clipboard::new() {
            let _ = clipboard.set_text("");
        }
        return process::ExitCode::SUCCESS;
    }

    match run(cli) {
        Ok(()) => process::ExitCode::SUCCESS,
        Err(msg) => {
            ui::error(&msg);
            process::ExitCode::FAILURE
        }
    }
}
