mod cli;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("rpki-ca: {error:#}");
        std::process::exit(1);
    }
}
