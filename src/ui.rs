use colored::Colorize;
use std::io::{self, Write};

pub(crate) const BANNER: &str = r"       _      ____
 ___  | | _  |___ \
/ __| | |/ /   __) |
\__ \ |   <   / __/
|___/ |_|\_\ |_____|
  simpleKeychain2";

pub(crate) fn colored_banner() -> String {
    format!("{}", BANNER.yellow().bold())
}

pub(crate) fn success(msg: &str) {
    println!("{}  {msg}", "[+]".green().bold());
}

pub(crate) fn error(msg: &str) {
    eprintln!("{} {msg}", "[!]".red().bold());
}

pub(crate) fn warning(msg: &str) {
    eprintln!("{} {msg}", "[!]".yellow().bold());
}

pub(crate) fn info(label: &str, value: &str) {
    println!("  {} {}", format!("{label}:").yellow().bold(), value.bold());
}

pub(crate) fn header(msg: &str) {
    println!("{}", msg.yellow().bold());
}

pub(crate) fn list_item(item: &str) {
    println!("  {} {item}", "›".yellow());
}

pub(crate) fn password_prompt(msg: &str) {
    eprint!("{} {}", "○━╡╞".green(), msg.yellow().bold());
    io::stderr().flush().unwrap();
}

pub(crate) fn service_password_prompt(msg: &str) {
    eprint!("{} {}", "○─┤├".blue().dimmed(), msg.yellow().bold());
    io::stderr().flush().unwrap();
}

pub(crate) fn input_prompt(msg: &str) {
    print!("{}  {}", "«◉»".truecolor(150, 100, 50), msg.yellow().bold());
    io::stdout().flush().unwrap();
}

pub(crate) fn plain_input_prompt(msg: &str) {
    print!("     {}", msg.yellow().bold());
    io::stdout().flush().unwrap();
}

#[cfg(any(feature = "export", feature = "import"))]
pub(crate) fn warning_block(lines: &[&str]) {
    for line in lines {
        eprintln!("{} {line}", "[!]".yellow().bold());
    }
}

pub(crate) fn get_service(value: &str) {
    println!("{}    {} {}", "⊙".truecolor(150, 100, 50), "Service:".yellow().bold(), value.bold());
}

pub(crate) fn get_username(value: &str) {
    println!("{}  {} {}", "«◉»".truecolor(150, 100, 50), "Username:".yellow().bold(), value.bold());
}

pub(crate) fn get_url(value: &str) {
    println!("     {} {}", "URL:".yellow().bold(), value.bold());
}

pub(crate) fn get_notes(value: &str) {
    println!("     {} {}", "Notes:".yellow().bold(), value.bold());
}

pub(crate) fn get_updated_at(ts: Option<i64>) {
    let age = match ts {
        None => "unknown".to_string(),
        Some(ts) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs() as i64;
            let days = (now - ts).max(0) / 86400;
            match days {
                0 => "today".to_string(),
                1 => "1 day ago".to_string(),
                n => format!("{n} days ago"),
            }
        }
    };
    println!("     {} {}", "Updated:".yellow().bold(), age);
}

pub(crate) fn list_item_stale(item: &str, age: &str) {
    println!("  {} {}  {}", "›".yellow(), item, age.dimmed());
}

pub(crate) fn list_item_pick(n: usize, item: &str) {
    println!("  {} {}", format!("[{n}]").yellow().bold(), item.bold());
}

pub(crate) fn clipboard_notice(label: &str, seconds: u64) {
    println!("{} {} copied to clipboard (will be cleared in {seconds}s)",
        "○─┤├".blue().dimmed(),
        label.yellow().bold(),
    );
}

pub(crate) fn muted(msg: &str) {
    println!("{}", msg.dimmed());
}

pub(crate) fn password_strength(entropy: f64) {
    let bits = format!("{entropy:.0} bits");
    if entropy < 40.0 {
        eprintln!("     Strength: {} (Weak)", bits.red().bold());
    } else if entropy < 64.0 {
        eprintln!("     Strength: {} (Fair)", bits.yellow().bold());
    } else if entropy < 80.0 {
        eprintln!("     Strength: {} (Strong)", bits.green().bold());
    } else {
        eprintln!("     Strength: {} (Very strong)", bits.green().bold());
    }
}

pub(crate) fn generate_warning() {
    eprintln!("{} This password is visible in your terminal. Only use {} for throwaway passwords.",
        "[!]".yellow().bold(),
        "generate".bold(),
    );
}

pub(crate) fn generated_password(pw: &str) {
    println!("     {} {}", "Password:".yellow().bold(), pw.bold());
}

#[cfg(any(feature = "export", feature = "import"))]
pub(crate) fn reminder(msg: &str) {
    println!("{}", msg.yellow().bold());
}
