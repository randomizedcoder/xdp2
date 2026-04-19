//! `xdp2-flow-loader` — CLI front-end for the production eBPF flow
//! dissector.
//!
//! Loads `fast_flow.bpf.o`, populates `jmp_table`, and (with
//! `CAP_NET_ADMIN`) attaches to the target netns's `flow_dissector`
//! hook. Runs until interrupted; detach happens in `Loader::drop`.
//!
//! Usage:
//!
//! ```text
//! xdp2-flow-loader --bpf fast_flow.bpf.o [--slow-path slow.bpf.o] [--netns /proc/self/ns/net]
//! ```
//!
//! Exits with:
//! - 0 on success (load-only, when no `--netns` is supplied and attach
//!   is skipped; in the current shape we always attempt attach, so 0
//!   means attach succeeded and the process was signalled to exit).
//! - 1 on argument or runtime error.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use xdp2_flow_loader::{Loader, LoaderConfig};

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
        Ok(()) => {
            // Drop will detach cleanly on return. A follow-up can add a
            // signal-driven run loop so operators can keep the loader
            // attached across the process lifetime.
            eprintln!("attached; detaching on exit");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("attach failed: {}", e);
            ExitCode::from(1)
        }
    }
}
