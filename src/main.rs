use clap::{Parser, Subcommand};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use renc::{Mode, RencError};

#[derive(Parser)]
#[command(name = "renc", version, about = "Rust Encryption Engine")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Keygen,
    Encrypt {
        file: PathBuf,
        #[arg(long)]
        password: bool,
        #[arg(long, value_name = "base64_pubkey")]
        to: Option<String>,
    },
    Decrypt {
        file: PathBuf,
    },
}

fn main() {
    if let Err(err) = run() {
        let _ = renc::utils::json::emit_error(err.code(), &err.message());
        std::process::exit(1);
    }
}

fn run() -> Result<(), RencError> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen => {
            let keypair = renc::generate_keypair()?;
            renc::utils::json::emit_keygen(&keypair.public_key_base64, &keypair.secret_key_base64)?;
        }
        Commands::Encrypt { file, password, to } => {
            if password == to.is_some() {
                return Err(RencError::InvalidArguments(
                    "Specify exactly one of --password or --to".to_string(),
                ));
            }
            let size = fs::metadata(&file)?.len();
            renc::utils::json::emit_start(&file, size)?;

            let output = encrypt_output_path(&file)?;
            let mut progress =
                |bytes: u64, percent: f64| renc::utils::json::emit_progress(bytes, percent);

            if password {
                let mut secret = read_stdin_secret()?;
                let result =
                    renc::encrypt_file_with_password(&file, &output, &secret, Some(&mut progress));
                secret.zeroize();
                let done = result?;
                renc::utils::json::emit_done(&done.output, &done.hash_hex)?;
            } else if let Some(recipient) = to {
                let done = renc::encrypt_file_with_pubkey(
                    &file,
                    &output,
                    &recipient,
                    Some(&mut progress),
                )?;
                renc::utils::json::emit_done(&done.output, &done.hash_hex)?;
            }
        }
        Commands::Decrypt { file } => {
            let header = renc::read_header_from_file(&file)?;
            let size = fs::metadata(&file)?.len();
            renc::utils::json::emit_start(&file, size)?;

            let output = decrypt_output_path(&file)?;
            let mut progress =
                |bytes: u64, percent: f64| renc::utils::json::emit_progress(bytes, percent);

            match header.mode {
                Mode::Password => {
                    let mut secret = read_stdin_secret()?;
                    let result = renc::decrypt_file_with_password(
                        &file,
                        &output,
                        &secret,
                        Some(&mut progress),
                    );
                    secret.zeroize();
                    let done = result?;
                    renc::utils::json::emit_done(&done.output, &done.hash_hex)?;
                }
                Mode::Pubkey => {
                    let secret = read_stdin_secret()?;
                    let mut secret_str = String::from_utf8(secret)
                        .map_err(|_| RencError::InvalidKey("Secret key must be UTF-8".into()))?;
                    let result = renc::decrypt_file_with_secret(
                        &file,
                        &output,
                        &secret_str,
                        Some(&mut progress),
                    );
                    secret_str.zeroize();
                    let done = result?;
                    renc::utils::json::emit_done(&done.output, &done.hash_hex)?;
                }
            }
        }
    }

    Ok(())
}

fn read_stdin_secret() -> Result<Vec<u8>, RencError> {
    let mut buffer = Vec::new();
    std::io::stdin().read_to_end(&mut buffer)?;
    while buffer.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        buffer.pop();
    }
    if buffer.is_empty() {
        return Err(RencError::InvalidArguments(
            "Secret input was empty".to_string(),
        ));
    }
    Ok(buffer)
}

fn encrypt_output_path(input: &Path) -> Result<PathBuf, RencError> {
    let file_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RencError::InvalidArguments("Invalid input filename".to_string()))?;
    let mut new_name = String::with_capacity(file_name.len() + 5);
    new_name.push_str(file_name);
    new_name.push_str(".renc");
    Ok(input.with_file_name(new_name))
}

fn decrypt_output_path(input: &Path) -> Result<PathBuf, RencError> {
    let file_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RencError::InvalidArguments("Invalid input filename".to_string()))?;
    let new_name = if let Some(stripped) = file_name.strip_suffix(".renc") {
        if stripped.is_empty() {
            "output".to_string()
        } else {
            stripped.to_string()
        }
    } else {
        format!("{file_name}.dec")
    };
    Ok(input.with_file_name(new_name))
}
