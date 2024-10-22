use clap::{Parser, ValueEnum};
use clio::{Input, Output};

mod crypto;
mod vault;

const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Parser)]
#[command(name = "Vaulter", about = "Secure AEAD file encryption utility")]
struct Cli {
    #[arg(short, long, value_name = "mode", value_enum)]
    mode: Modes,
    #[arg(
        short,
        long,
        value_name = "input file path",
        help = "Input file, if not provided, stdin will be used",
        default_value = "-"
    )]
    input: Input,
    #[arg(
        short,
        long,
        value_name = "output file path",
        help = "Output file, if not provided, stdout will be used",
        default_value = "-"
    )]
    output: Output,
    #[arg(short, long, value_name = "key", help = "Encryption key")]
    key: String,
    #[arg(short, long, value_name = "size", help = "Chunk size in bytes", default_value_t=DEFAULT_CHUNK_SIZE)]
    chunk_size: usize,
}

#[derive(ValueEnum, Clone)]
enum Modes {
    Lock,
    Unlock,
}

fn main() {
    let cli = Cli::parse();

    match cli.mode {
        Modes::Lock => {
            let mut chunk_size = cli
                .input
                .len()
                .unwrap_or(cli.chunk_size as u64)
                .try_into()
                .unwrap();
            if chunk_size > cli.chunk_size {
                chunk_size = cli.chunk_size;
            }

            vault::buffer_encrypt(cli.input, cli.output, cli.key.as_bytes(), chunk_size);
        }
        Modes::Unlock => {
            vault::buffer_decrypt(cli.input, cli.output, cli.key.as_bytes());
        }
    }
}
