mod cli;
mod daemon;
mod pam_auth;

fn main() {
    if let Err(error) = run() {
        eprintln!("passkey: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref().unwrap_or("status") {
        "daemon" => daemon::run(),
        "pam-auth" => pam_auth::run(args.collect()),
        command => cli::run(command, args.collect()),
    }
}
