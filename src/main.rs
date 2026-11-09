use std::path::PathBuf;
use std::process::ExitCode;

use chaosreader2026::generate_case_dir;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "chaosreader2026",
    version,
    about = "Reconstruct sessions, transcripts, and artifacts from pcap/pcapng captures"
)]
struct Cli {
    /// Input packet capture (.pcap or .pcapng)
    input: PathBuf,

    /// Output directory for index.html, sessions.jsonl, and reconstructed artifacts
    #[arg(short = 'o', long = "output-dir", default_value = "chaosreader_out")]
    output_dir: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match generate_case_dir(&cli.input, &cli.output_dir) {
        Ok(summaries) => {
            println!(
                "Reconstructed {} session(s) -> {}",
                summaries.len(),
                cli.output_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
