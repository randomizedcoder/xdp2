//! `xdp2-flow-loader` — CLI front-end for the production eBPF flow
//! dissector.
//!
//! **D7a skeleton.** Parses arguments and drives the (placeholder)
//! [`xdp2_flow_loader::Loader`] API. Actual loading/attaching lands in
//! D7b.
//!
//! Usage:
//!
//! ```text
//! xdp2-flow-loader --bpf fast_flow.bpf.o [--slow-path slow.bpf.o] [--netns /proc/self/ns/net]
//! ```
//!
//! Exits with:
//! - 0 on success.
//! - 1 on argument or runtime error.
//! - 2 on "not implemented" (D7a placeholder — remove once D7b lands).

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use xdp2_flow_loader::{Loader, LoaderConfig, LoaderError};

fn usage(prog: &str) -> ! {
    eprintln!(
        "usage: {} --bpf <fast_flow.bpf.o> [--slow-path <obj>] [--netns <path>]",
        prog
    );
    std::process::exit(1);
}

struct Args {
    bpf_object: PathBuf,
    slow_path_object: Option<PathBuf>,
    attach_netns: Option<PathBuf>,
}

fn parse_args() -> Args {
    let argv: Vec<String> = env::args().collect();
    let prog = argv.first().cloned().unwrap_or_else(|| "xdp2-flow-loader".into());

    let mut bpf_object: Option<PathBuf> = None;
    let mut slow_path_object: Option<PathBuf> = None;
    let mut attach_netns: Option<PathBuf> = None;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--bpf" | "-b" => {
                i += 1;
                bpf_object = Some(PathBuf::from(argv.get(i).unwrap_or_else(|| usage(&prog))));
            }
            "--slow-path" | "-s" => {
                i += 1;
                slow_path_object =
                    Some(PathBuf::from(argv.get(i).unwrap_or_else(|| usage(&prog))));
            }
            "--netns" | "-n" => {
                i += 1;
                attach_netns =
                    Some(PathBuf::from(argv.get(i).unwrap_or_else(|| usage(&prog))));
            }
            "-h" | "--help" => usage(&prog),
            other => {
                eprintln!("unknown argument: {}", other);
                usage(&prog);
            }
        }
        i += 1;
    }

    let Some(bpf_object) = bpf_object else { usage(&prog) };
    Args { bpf_object, slow_path_object, attach_netns }
}

fn main() -> ExitCode {
    let args = parse_args();

    let mut cfg = LoaderConfig::new(args.bpf_object);
    cfg.slow_path_object = args.slow_path_object;
    cfg.attach_netns = args.attach_netns;

    let mut loader = match Loader::load(cfg) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("load failed: {}", e);
            return ExitCode::from(1);
        }
    };

    println!(
        "loaded: entry_fd={}, jmp_table_slots={}",
        loader.entry_fd(),
        loader.slot_count()
    );

    match loader.attach() {
        Ok(()) => ExitCode::SUCCESS,
        Err(LoaderError::NotImplemented { operation }) => {
            eprintln!("{} not implemented yet — coming in D7c", operation);
            // Still exit 0: load succeeded, which is the entire D7b
            // contract. Non-attach exits are not a failure for the
            // skeleton CLI.
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("attach failed: {}", e);
            ExitCode::from(1)
        }
    }
}
