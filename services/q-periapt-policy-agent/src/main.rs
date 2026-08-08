//! Policy-agent executable with an explicit fail-closed non-Unix entry point.

#[cfg(unix)]
fn main() {
    if let Err(error) = q_periapt_policy_agent::ipc::run_from_arguments(std::env::args_os()) {
        eprintln!("policy agent terminated: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("policy agent terminated: Unix owner-only IPC boundary is unavailable");
    std::process::exit(1);
}
