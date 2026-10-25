use std::process::Command;

fn lin(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lin"))
        .args(args)
        .env_remove("LINEAR_API_TOKEN")
        .output()
        .expect("run lin")
}

#[test]
fn bad_arguments_are_json_usage_errors() {
    let out = lin(&["auth", "nope"]);
    assert_eq!(out.status.code(), Some(2));
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).expect("JSON on stderr");
    assert_eq!(err["error"]["code"], "usage_error");
}

#[test]
fn bad_arguments_in_human_mode() {
    let out = lin(&["--human", "auth", "login", "--scope"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("error: "));
}

#[test]
fn help_and_version_still_work() {
    let out = lin(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("lin "));
    assert_eq!(lin(&["--help"]).status.code(), Some(0));
}
