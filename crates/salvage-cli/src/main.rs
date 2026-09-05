use salvage_core::manifest::{SUPPORTED_SCHEMA_VERSION, manifest_hash, parse_manifest_bytes};
use salvage_core::workspace_check;

const USAGE: &str = "salvage check | salvage manifest check <path>";

fn json_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}

fn manifest_check(path: &str) -> (i32, String) {
    // Read raw bytes: undecodable (non-UTF-8) input is malformed manifest
    // content (`manifest/parse`, exit 1), while a missing/unreadable file
    // is an I/O problem (`io`, exit 2).
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                2,
                format!(
                    r#"{{"status":"error","code":"io","message":"cannot read {}: {}"}}"#,
                    json_escape(path),
                    json_escape(&error.to_string())
                ),
            );
        }
    };
    match parse_manifest_bytes(&bytes) {
        Ok(manifest) => (
            0,
            format!(
                r#"{{"status":"ok","command":"manifest-check","schema_version":"{SUPPORTED_SCHEMA_VERSION}","manifest_hash":"{}"}}"#,
                manifest_hash(&manifest)
            ),
        ),
        Err(error) => (
            1,
            format!(
                r#"{{"status":"error","code":"{}","message":"{}"}}"#,
                json_escape(error.code()),
                json_escape(&error.message())
            ),
        ),
    }
}

fn response(args: &[String]) -> (i32, String) {
    match args {
        [command] if command == "check" => (0, workspace_check().to_json()),
        [first, second, path] if first == "manifest" && second == "check" => manifest_check(path),
        [command] if command == "--version" || command == "-V" => (
            0,
            format!(
                r#"{{"status":"ok","command":"version","version":"{}"}}"#,
                env!("CARGO_PKG_VERSION")
            ),
        ),
        [command] if command == "--help" || command == "-h" => (
            0,
            format!(r#"{{"status":"ok","command":"help","usage":"{}"}}"#, USAGE),
        ),
        _ => (
            2,
            format!(
                r#"{{"status":"error","code":"usage","message":"expected `{}`"}}"#,
                USAGE
            ),
        ),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (exit_code, output) = response(&args);

    if exit_code == 0 {
        println!("{output}");
    } else {
        eprintln!("{output}");
    }

    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::response;

    #[test]
    fn invalid_arguments_return_a_usage_error() {
        let args = vec!["restore".to_owned()];

        assert_eq!(
            response(&args),
            (
                2,
                r#"{"status":"error","code":"usage","message":"expected `salvage check | salvage manifest check <path>`"}"#
                    .to_owned()
            )
        );
    }
}
