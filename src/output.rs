use serde_json::Value;

use crate::error::Error;

#[derive(Clone, Copy)]
pub enum Format {
    Json,
    Human,
}

/// Results go to stdout as one line of JSON (cheap for agents to parse), or
/// as indented `key: value` lines with `--human`.
pub fn print(format: Format, value: &Value) {
    match format {
        Format::Json => println!("{value}"),
        Format::Human => {
            let mut out = String::new();
            render(value, 0, &mut out);
            print!("{out}");
        }
    }
}

/// Errors go to stderr, in the same format as results.
pub fn print_error(format: Format, err: &Error) {
    match format {
        Format::Json => eprintln!("{}", err.to_json()),
        Format::Human => eprintln!("error: {err}"),
    }
}

fn render(value: &Value, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                match v {
                    Value::Object(m) if !m.is_empty() => {
                        out.push_str(&format!("{pad}{k}:\n"));
                        render(v, indent + 1, out);
                    }
                    _ => out.push_str(&format!("{pad}{k}: {}\n", scalar(v))),
                }
            }
        }
        other => out.push_str(&format!("{pad}{}\n", scalar(other))),
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        Value::Array(a) => a.iter().map(scalar).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn human_rendering() {
        let mut out = String::new();
        render(
            &json!({ "a": "x", "b": { "c": 1 }, "d": ["p", "q"], "e": null }),
            0,
            &mut out,
        );
        assert_eq!(out, "a: x\nb:\n  c: 1\nd: p, q\ne: -\n");
    }
}
