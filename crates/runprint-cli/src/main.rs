mod trace;

use anyhow::Result;
use clap::{Parser, Subcommand};
use runprint_core::{diff, Behavior, BehaviorLock};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "runprint", version, about = "A lockfile for runtime behavior")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Record {
        #[arg(short, long, default_value = "behavior.lock")]
        output: PathBuf,

        #[arg(long)]
        include_system: bool,

        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    Diff {
        old: PathBuf,
        new: PathBuf,
    },

    Check {
        #[arg(short, long, default_value = "behavior.lock")]
        baseline: PathBuf,

        #[arg(long)]
        include_system: bool,

        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Record {
            output,
            include_system,
            command,
        } => {
            let run = trace::record(&command, include_system)?;
            save(&output, &run.lock)?;

            let counts = run.lock.counts();

            println!();
            println!("Runprint");
            println!();
            println!("exec       {}", counts.exec);
            println!("file read  {}", counts.file_read);
            println!("file write {}", counts.file_write);
            println!("delete     {}", counts.file_delete);
            println!("rename     {}", counts.file_rename);
            println!("mkdir      {}", counts.directory_create);
            println!("rmdir      {}", counts.directory_delete);
            println!("symlink    {}", counts.symlink_create);
            println!("hardlink   {}", counts.hardlink_create);
            println!("network    {}", counts.network);
            println!("unix       {}", counts.unix);
            println!("-----------");
            println!("total      {}", counts.total());
            println!();
            println!("digest     {}", run.lock.digest()?);
            println!("exit       {}", run.exit_code);
            println!("saved      {}", output.display());

            if run.exit_code != 0 {
                std::process::exit(run.exit_code);
            }
        }

        Commands::Diff { old, new } => {
            let old = load(&old)?;
            let new = load(&new)?;
            let d = diff(&old, &new);

            if d.added.is_empty() && d.removed.is_empty() {
                println!("runtime behavior unchanged");
                return Ok(());
            }

            for item in &d.added {
                println!("+ {}", render(item));
            }

            for item in &d.removed {
                println!("- {}", render(item));
            }
        }

        Commands::Check {
            baseline,
            include_system,
            command,
        } => {
            let expected = load(&baseline)?;
            let run = trace::record(&command, include_system)?;
            let d = diff(&expected, &run.lock);

            if d.added.is_empty() && d.removed.is_empty() {
                println!();
                println!("runtime behavior unchanged");

                if run.exit_code != 0 {
                    eprintln!("command exited with {}", run.exit_code);
                    std::process::exit(run.exit_code);
                }

                return Ok(());
            }

            println!();
            println!("RUNTIME BEHAVIOR CHANGED");
            println!();

            for item in &d.added {
                println!("+ {}", render(item));
            }

            for item in &d.removed {
                println!("- {}", render(item));
            }

            std::process::exit(10);
        }
    }

    Ok(())
}

fn save(path: &Path, lock: &BehaviorLock) -> Result<()> {
    fs::write(path, lock.canonical_json()?)?;
    Ok(())
}

fn load(path: &Path) -> Result<BehaviorLock> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn render(item: &Behavior) -> String {
    match item {
        Behavior::Exec { path } => format!("exec     {path}"),
        Behavior::FileRead { path } => format!("read     {path}"),
        Behavior::FileWrite { path } => format!("write    {path}"),
        Behavior::FileDelete { path } => format!("delete   {path}"),
        Behavior::FileRename { from, to } => format!("rename   {from} -> {to}"),
        Behavior::DirectoryCreate { path } => format!("mkdir    {path}"),
        Behavior::DirectoryDelete { path } => format!("rmdir    {path}"),
        Behavior::SymlinkCreate { target, link } => {
            format!("symlink  {link} -> {target}")
        }
        Behavior::HardlinkCreate { from, to } => {
            format!("hardlink {from} -> {to}")
        }
        Behavior::NetworkConnect { address } => format!("connect  {address}"),
        Behavior::UnixConnect { path } => format!("ipc      {path}"),
    }
}
