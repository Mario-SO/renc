use serde::Serialize;
use std::io::{self, Write};
use std::path::Path;

use crate::RencError;

#[derive(Serialize)]
struct StartEvent<'a> {
    event: &'static str,
    file: &'a str,
    size: u64,
}

#[derive(Serialize)]
struct ProgressEvent {
    event: &'static str,
    bytes: u64,
    percent: f64,
}

#[derive(Serialize)]
struct DoneEvent<'a> {
    event: &'static str,
    output: &'a str,
    hash: &'a str,
}

#[derive(Serialize)]
struct ErrorEvent<'a> {
    event: &'static str,
    code: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct KeygenEvent<'a> {
    event: &'static str,
    public_key: &'a str,
    secret_key: &'a str,
}

fn emit<T: Serialize>(event: &T) -> Result<(), RencError> {
    let json = serde_json::to_string(event)
        .map_err(|err| RencError::Io(format!("JSON serialize failed: {err}")))?;
    let mut stdout = io::stdout();
    writeln!(stdout, "{json}")?;
    stdout.flush()?;
    Ok(())
}

pub fn emit_start(path: &Path, size: u64) -> Result<(), RencError> {
    let file = path
        .to_str()
        .ok_or_else(|| RencError::InvalidArguments("Invalid path".to_string()))?;
    emit(&StartEvent {
        event: "start",
        file,
        size,
    })
}

/// Emit a progress JSON event.
pub fn emit_progress(bytes: u64, percent: f64) -> Result<(), RencError> {
    emit(&ProgressEvent {
        event: "progress",
        bytes,
        percent,
    })
}

/// Emit a done JSON event.
pub fn emit_done(path: &Path, hash: &str) -> Result<(), RencError> {
    let output = path
        .to_str()
        .ok_or_else(|| RencError::InvalidArguments("Invalid path".to_string()))?;
    emit(&DoneEvent {
        event: "done",
        output,
        hash,
    })
}

/// Emit an error JSON event.
pub fn emit_error(code: &str, message: &str) -> Result<(), RencError> {
    emit(&ErrorEvent {
        event: "error",
        code,
        message,
    })
}

/// Emit a keygen JSON event.
pub fn emit_keygen(public_key: &str, secret_key: &str) -> Result<(), RencError> {
    emit(&KeygenEvent {
        event: "keygen",
        public_key,
        secret_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_event_serialization() {
        let event = StartEvent {
            event: "start",
            file: "/tmp/file",
            size: 12,
        };
        let json = serde_json::to_string(&event).expect("json");
        assert_eq!(json, r#"{"event":"start","file":"/tmp/file","size":12}"#);
    }

    #[test]
    fn done_event_serialization() {
        let event = DoneEvent {
            event: "done",
            output: "/tmp/out",
            hash: "abc123",
        };
        let json = serde_json::to_string(&event).expect("json");
        assert_eq!(json, r#"{"event":"done","output":"/tmp/out","hash":"abc123"}"#);
    }
}
