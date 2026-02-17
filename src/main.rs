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
    /// Add or update a credential (use --generate for a random password)
    Add {
        /// The service name (e.g. "github", "gmail")
        service: String,
        /// Generate a random password instead of prompting for one
        #[arg(short, long)]
        generate: bool,
        /// Length of the generated password (default: 16, range: 4–64)
        #[arg(short, long, default_value_t = 16)]
        length: usize,
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
    List,
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

        Command::Add { service, generate, length } => {
            let key = vault::unlock_vault(&conn)?;
            let username = vault::prompt("Username: ");

            let password = if generate {
                if !(4..=64).contains(&length) {
                    return Err("Password length must be between 4 and 64.".into());
                }
                crypto::generate_password(length)
            } else {
                if length != 16 {
                    return Err("--length requires --generate.".into());
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

            db::add_credential(&conn, &key, &service, &username, &password);
            ui::success(&format!("Credential stored for '{service}'."));
        }

        Command::Get { service } => {
            let key = vault::unlock_vault(&conn)?;
            match db::get_credential(&conn, &key, &service) {
                Some((username, password)) => {
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

                    ui::info("Service ", &service);
                    ui::info("Username", &username);
                    ui::success(&format!("Password copied to clipboard (will be cleared in {CLIPBOARD_CLEAR_SECONDS}s)."));
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

        Command::List => {
            vault::unlock_vault(&conn)?;
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
