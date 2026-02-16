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
    println!("{} {msg}", "[+]".green().bold());
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
    print!("{} {}", "«◉»".truecolor(150, 100, 50), msg.yellow().bold());
    io::stdout().flush().unwrap();
}

#[cfg(feature = "export")]
pub(crate) fn warning_block(lines: &[&str]) {
    for line in lines {
        eprintln!("{} {line}", "[!]".yellow().bold());
    }
}

pub(crate) fn muted(msg: &str) {
    println!("{}", msg.dimmed());
}

#[cfg(feature = "export")]
pub(crate) fn reminder(msg: &str) {
    println!("{}", msg.yellow().bold());
}
