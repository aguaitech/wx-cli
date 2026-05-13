mod cli;
mod config;
mod crypto;
mod daemon;
mod ipc;
mod scanner;

fn main() {
    if std::env::var("WX_DAEMON_MODE").is_ok() {
        daemon::run();
    } else {
        cli::run();
    }
}
