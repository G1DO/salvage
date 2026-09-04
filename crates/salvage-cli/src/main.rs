use salvage_core::workspace_check;

const USAGE: &str = "salvage check";

fn response(args: &[String]) -> (i32, String) {
    match args {
        [command] if command == "check" => (0, workspace_check().to_json()),
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
                r#"{"status":"error","code":"usage","message":"expected `salvage check`"}"#
                    .to_owned()
            )
        );
    }
}
