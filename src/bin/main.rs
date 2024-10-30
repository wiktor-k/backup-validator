use std::{io::Write, path::PathBuf};

use clap::Parser;

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long)]
    password: PathBuf,

    #[clap(short, long)]
    backup: PathBuf,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    List,
    Dump(DumpCommand),
}

#[derive(Debug, Parser)]
struct DumpCommand {
    key: String,
}

use nethsm_backup::Backup;

fn main() -> testresult::TestResult {
    let args = Args::parse();
    let backup = Backup::parse(std::fs::File::open(args.backup)?)?;
    let decryptor = backup.decrypt(&std::fs::read(args.password)?)?;
    match args.command {
        Command::List => {
            for item in decryptor.items_iter() {
                let key = item?.0;
                println!("{key}");
            }
        }
        Command::Dump(dump) => {
            let items = decryptor
                .items_iter()
                .flat_map(|item| item.ok())
                .filter(|(key, _)| dump.key == *key);
            for item in items {
                std::io::stdout().write_all(&item.1)?;
            }
        }
    }
    Ok(())
}
