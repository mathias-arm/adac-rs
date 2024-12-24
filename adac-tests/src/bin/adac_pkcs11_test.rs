// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac_tests::pkcs11;
use clap::{Parser, Subcommand};
use console::Emoji;
use indicatif::FormattedDuration;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[clap(version)]
struct Args {
    #[clap(short = 'p', long, env)]
    profile_path: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Check {
        #[clap(short, long)]
        module: String,
        #[clap(short, long)]
        pin: String,
        #[clap(short, long)]
        label: Option<String>,
    },
    Test {
        #[clap(short, long)]
        module: String,
        #[clap(short, long)]
        pin: String,
        #[clap(short, long)]
        label: Option<String>,
    },
}

static SPARKLE: Emoji<'_, '_> = Emoji("✨ ", ":-)");

fn main() {
    let args = Args::parse();

    match args.cmd {
        Commands::Check { module, pin, label } => {
            let started = Instant::now();
            pkcs11::adac_check(module, pin, label);
            println!(
                "{} Done in {}",
                SPARKLE,
                FormattedDuration(started.elapsed())
            );
        }
        Commands::Test { module, pin, label } => {
            let started = Instant::now();
            pkcs11::adac_test(module, pin, label);
            println!(
                "\n{} Done in {}",
                SPARKLE,
                FormattedDuration(started.elapsed())
            );
        }
    }
}
